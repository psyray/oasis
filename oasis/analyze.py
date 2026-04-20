import argparse
import json
import logging
import re
import sys
import time as time_module
from contextlib import suppress
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union

from pydantic import BaseModel, ValidationError
from tqdm import tqdm
from multiprocessing import Pool, cpu_count

# Import from configuration
from .config import (
    CHUNK_ANALYZE_TIMEOUT,
    CHUNK_DEEP_NUM_PREDICT,
    CONTEXT_EXPAND_MAX_CHARS,
    LANGUAGES,
    MODEL_EMOJIS,
    VULNERABILITY_PROMPT_EXTENSION,
    EMBEDDING_THRESHOLDS,
    MAX_CHUNK_SIZE,
    DEFAULT_ARGS,
)

# Import from other modules
from .ollama_manager import OllamaManager
from .helpers.misc import absolute_snippet_lines_in_file
from .tools import chunk_content_with_spans, logger, calculate_similarity, sanitize_name
from .report import (
    Report,
    progress_timestamp_iso,
    publish_incremental_summary,
)
from .helpers import (
    reset_tqdm_phase_bar,
    safe_code_base_file_count,
    standard_deep_phase_extras,
)
from .helpers.langgraph_cli import (
    LG_DEBUG_SEPARATOR,
    LG_DEEP_VULN_FINISHED,
    LG_LLM_SELECTED,
    LG_SCAN_TASK_COMPLETE,
    cli_bold,
    deep_payload_vuln_types_total,
    embedding_tasks_vuln_types_total,
    langgraph_emit,
    langgraph_emit_post_pipeline,
    llm_debug_log_request,
    llm_debug_log_response,
    separator_file_scope,
    separator_vulnerability,
)
from .helpers.context_expand import expand_suspicious_chunk_records
from .helpers.poc import (
    POC_DIGEST_JSON_MAX_CHARS,
    build_compact_findings_digest,
    build_poc_hints_markdown,
    finalize_poc_digest_json,
    maybe_debug_log_poc_stage_output,
    poc_assist_chat_options,
)
from .helpers.progress import (
    EXEC_SUMMARY_PROGRESS_EVENT_VERSION,
    graph_final_phases,
    graph_phases_deep_in_progress,
    graph_phases_discover_done_scan_pending,
    graph_phases_scan_done_expand_pending,
    graph_progress_extras,
)
from .embedding import EmbeddingManager, build_vulnerability_embedding_prompt
from .cache import CacheManager
from .enums import AnalysisMode
from .schemas.analysis import (
    ANALYSIS_SCHEMA_VERSION,
    ChunkDeepAnalysis,
    MediumRiskAnalysis,
    ScanVerdict,
    VulnerabilityFinding,
    chunk_analysis_to_markdown,
)
from .helpers.misc import structured_deep_raw_looks_degenerate
from .structured_output.deep import (
    chunk_deep_degenerate_retry_suffix,
    chunk_deep_normalization_change_samples,
    chunk_deep_prompt_output_constraint_block,
    chunk_deep_structured_retry_suffix,
    generic_structured_retry_suffix,
    normalize_chunk_deep_payload_dict,
    validation_detail_is_exploitation_conditions_retryable,
)
from .structured_output.json_repair import (
    build_safe_minimal_chunk_json,
    repair_chunk_deep_structured_json_raw,
)

STRUCTURED_OUTPUT_RAW_PREVIEW_MAX_LEN = 500


def _publish_exec_summary_progress(
    analyzer: Any,
    report: Report,
    all_results: Dict[str, Any],
    *,
    completed_vulnerabilities: int,
    total_vulnerabilities: int,
    current_vulnerability: Optional[str],
    tested_vulnerabilities: List[str],
    **progress_extras: Any,
) -> None:
    """Emit executive-summary progress; pins ``event_version`` and model from ``analyzer``."""
    publish_incremental_summary(
        report,
        analyzer.llm_model,
        all_results,
        completed_vulnerabilities=completed_vulnerabilities,
        total_vulnerabilities=total_vulnerabilities,
        current_vulnerability=current_vulnerability,
        tested_vulnerabilities=tested_vulnerabilities,
        event_version=EXEC_SUMMARY_PROGRESS_EVENT_VERSION,
        **progress_extras,
    )


def _langgraph_publish_mid_pipeline(
    analyzer: Any,
    report: Optional[Report],
    *,
    nv: int,
    phases: List[Dict[str, Any]],
) -> None:
    """Shared LangGraph snapshot: zero completed vulns, pipeline phase rows only."""
    if report is None:
        return
    _publish_exec_summary_progress(
        analyzer,
        report,
        {},
        completed_vulnerabilities=0,
        total_vulnerabilities=nv,
        current_vulnerability=None,
        tested_vulnerabilities=[],
        **graph_progress_extras(analyzer=analyzer, nv=nv, phases=phases),
    )


def _enrich_findings_with_snippet_file_lines(
    chunk_model: ChunkDeepAnalysis,
    chunk_text: str,
    file_chunk_start: Optional[int],
) -> ChunkDeepAnalysis:
    """Attach snippet_start_line/snippet_end_line when vulnerable_code matches the chunk."""
    if not isinstance(file_chunk_start, int) or file_chunk_start < 1:
        return chunk_model
    new_findings: List[VulnerabilityFinding] = []
    changed = False
    for finding in chunk_model.findings:
        span = absolute_snippet_lines_in_file(
            chunk_text, file_chunk_start, finding.vulnerable_code
        )
        if span is None:
            new_findings.append(finding)
        else:
            a, b = span
            new_findings.append(
                finding.model_copy(update={"snippet_start_line": a, "snippet_end_line": b})
            )
            changed = True
    if not changed:
        return chunk_model
    return chunk_model.model_copy(update={"findings": new_findings})

# Define analysis modes and types
# Handler receives either ValidationError (schema mismatch) or runtime/transport exceptions.
StructuredOutputFailureHandler = Callable[
    [Type[BaseModel], str, Exception, str],
    Optional[str],
]


class SecurityAnalyzer:
    """Embeddings, caching, prompts, structured outputs, and vulnerability analysis.

    **LangGraph (canonical product pipeline):** orchestration lives in ``oasis/agent/``
    (``graph.py``, ``invoke.invoke_oasis_langgraph``, ``tools.py`` / ``nodes.py``). Nodes call
    only the ``langgraph_*`` methods below—do not reimplement Discover→Scan→… sequencing in
    ``oasis.py`` or helpers.

    LangGraph hooks (invoked by the agent layer):
        ``langgraph_discover_and_publish``, ``langgraph_scan_and_publish``,
        ``langgraph_expand_and_publish``, ``langgraph_deep_and_publish``,
        ``langgraph_verify``, ``langgraph_finalize_reports``, ``langgraph_poc_assist``.

    Entry: ``process_analysis_with_model`` → ``invoke_oasis_langgraph``.
    """

    def __init__(self, args, llm_model: str, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager,
                 scan_model: str = None,
                 structured_output_failure_handler: Optional[StructuredOutputFailureHandler] = None):
        """
        Initialize the security analyzer with support for tiered model analysis.

        Args:
            args: Command line arguments
            llm_model: Main model to use for deep analysis
            embedding_manager: Embedding manager to use for embeddings
            ollama_manager: Ollama manager for model interactions
            scan_model: Lightweight model for initial scanning (if None, uses llm_model)
        """
        try:
            self.ollama_manager = ollama_manager
            self.client = self.ollama_manager.get_client()
        except Exception as e:
            logger.error("Failed to initialize Ollama client")
            logger.error("Please make sure Ollama is running and accessible")
            logger.exception(f"Initialization error: {str(e)}")
            raise RuntimeError("Could not connect to Ollama server") from e

        self.args = args

        # Set up primary (deep) model
        self.llm_model = llm_model
        
        # Set up scanning model (lighter model for initial passes)
        self.scan_model = scan_model or llm_model
        self.ollama_manager.ensure_model_available(self.scan_model)
        logger.info(
            f"{MODEL_EMOJIS['default']} Using {cli_bold(self.ollama_manager.get_model_display_name(self.scan_model))} "
            f"for initial scanning and {cli_bold(self.ollama_manager.get_model_display_name(self.llm_model))} for deep analysis"
        )
        
        self.embedding_manager = embedding_manager
        self.embedding_model = embedding_manager.embedding_model
        self.code_base = embedding_manager.code_base
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.threshold = embedding_manager.threshold
        
        # Cache parameters
        self.clear_cache_scan = args.clear_cache_scan if hasattr(args, 'clear_cache_scan') else False
        self.cache_days = args.cache_days if hasattr(args, 'cache_days') else DEFAULT_ARGS['CACHE_DAYS']
        
        # Cache for suspicious sections (to avoid re-scanning)
        self.suspicious_sections = {}
        
        # Initialize the cache manager for scan/deep/graph analysis artifacts
        self.cache_manager = CacheManager(
            input_path=embedding_manager.input_path,
            llm_model=self.llm_model,
            scan_model=self.scan_model,
            cache_days=self.cache_days
        )
        
        self.structured_output_failure_handler = structured_output_failure_handler
        self.run_id = getattr(args, "run_id", None)
        self.language_code = getattr(args, "language", "en")
        self.language = LANGUAGES.get(self.language_code, LANGUAGES["en"])

        if hasattr(self, 'clear_cache_scan') and self.clear_cache_scan:
            self.cache_manager.clear_scan_cache()

    def _default_structured_output_failure(
        self,
        response_model: Type[BaseModel],
        error: Exception,
    ) -> str:
        if issubclass(response_model, ScanVerdict):
            return "ERROR"
        if issubclass(response_model, MediumRiskAnalysis):
            return MediumRiskAnalysis(
                risk_score=50,
                analysis=f"Structured output failure: {error}",
                validation_error=True,
            ).model_dump_json()
        return ChunkDeepAnalysis(
            findings=[],
            notes=f"Structured output failure: {error}",
            validation_error=True,
        ).model_dump_json()

    def _resolve_structured_output_failure(
        self,
        response_model: Type[BaseModel],
        raw: str,
        error: Exception,
        model_display: str,
    ) -> str:
        """Resolve structured-output failure from either validation or transport/runtime errors."""
        handler = self.structured_output_failure_handler
        if handler is not None:
            handled = handler(response_model, raw, error, model_display)
            if handled is not None:
                return handled
        return self._default_structured_output_failure(response_model, error)

    def _parse_structured_output_response(
        self,
        raw: str,
        response_model: Type[BaseModel],
        model_display: str,
        file_path: Optional[str] = None,
        vuln_name: Optional[str] = None,
        retry_attempt: Optional[int] = None,
        retry_max: Optional[int] = None,
        raise_validation_error: bool = False,
    ) -> str:
        """
        Parse and normalize structured LLM output for one response model.

        Contract:
        - Scan models return a plain verdict string.
        - Non-scan models return JSON serialized by the target Pydantic schema.
        - Validation failures are converted through the structured fallback strategy.

        **Raw variables (ChunkDeep / scan JSON path):**

        - ``original_raw``: immutable copy of the model string for logging and for the
          structured failure handler (so diagnostics always show what the API returned).
        - ``candidate_raw``: text passed to ``model_validate_json`` — starts as
          normalized output (e.g. list→string coercion for ChunkDeep); may be replaced by
          ``repaired_raw`` when JSON repair succeeds after a repairable parse error.
        - ``repaired_raw``: optional output of ``_repair_structured_json_raw`` when the
          first validation error looks like broken JSON (not a field-type mismatch);
          used only to retry validation, not as the logged ``original_raw``.
        """
        original_raw = raw
        candidate_raw = self._normalize_structured_output_raw(
            raw=raw,
            response_model=response_model,
            model_display=model_display,
        )
        try:
            parsed = response_model.model_validate_json(candidate_raw)
        except ValidationError as exc:
            candidate_raw, repaired_parsed = self._attempt_structured_json_repair_after_validation_error(
                candidate_raw=candidate_raw,
                response_model=response_model,
                model_display=model_display,
                error=exc,
            )
            if repaired_parsed is not None:
                if issubclass(response_model, ScanVerdict):
                    return repaired_parsed.verdict
                return repaired_parsed.model_dump_json()
            phase_name = "scan" if issubclass(response_model, ScanVerdict) else "deep"
            self._log_structured_output_error(
                phase=phase_name,
                response_model=response_model,
                model_display=model_display,
                raw=original_raw,
                error=exc,
                file_path=file_path,
                vuln_name=vuln_name,
                retry_attempt=retry_attempt,
                retry_max=retry_max,
            )
            logger.warning(f"Structured output validation failed ({model_display}): {exc}")
            raw_preview = (original_raw or "")[:STRUCTURED_OUTPUT_RAW_PREVIEW_MAX_LEN]
            if len(original_raw or "") > STRUCTURED_OUTPUT_RAW_PREVIEW_MAX_LEN:
                raw_preview += "... [truncated]"
            logger.debug(f"Structured output raw preview ({model_display}): {raw_preview}")
            if raise_validation_error:
                raise
            return self._resolve_structured_output_failure(
                response_model=response_model,
                raw=original_raw,
                error=exc,
                model_display=model_display,
            )

        if issubclass(response_model, ScanVerdict):
            return parsed.verdict
        return parsed.model_dump_json()

    def _attempt_structured_json_repair_after_validation_error(
        self,
        *,
        candidate_raw: str,
        response_model: Type[BaseModel],
        model_display: str,
        error: ValidationError,
    ) -> Tuple[str, Optional[BaseModel]]:
        """
        When validation failed, optionally run JSON repair and re-parse.

        Returns ``(candidate_raw, None)`` if repair is not applicable or did not help.
        On success returns ``(repaired_raw, parsed_model)`` so the caller can serialize
        the repaired object without re-running repair.
        """
        if not self._is_repairable_structured_error(error=error):
            return candidate_raw, None
        repaired_raw = self._repair_structured_json_raw(
            raw=candidate_raw,
            response_model=response_model,
            model_display=model_display,
        )
        if repaired_raw == candidate_raw:
            return candidate_raw, None
        with suppress(ValidationError):
            repaired_parsed = response_model.model_validate_json(repaired_raw)
            return repaired_raw, repaired_parsed
        return candidate_raw, None

    def _normalize_structured_output_raw(
        self,
        *,
        raw: str,
        response_model: Type[BaseModel],
        model_display: str,
    ) -> str:
        """Normalize frequent non-breaking type drifts before schema validation."""
        if not raw or not issubclass(response_model, ChunkDeepAnalysis):
            return raw

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            logger.debug(
                "Structured output normalization skipped: JSON parse failed (%s): %s",
                model_display,
                exc,
            )
            return raw
        except (TypeError, ValueError) as exc:
            logger.debug(
                "Structured output normalization skipped: not valid JSON input (%s): %s",
                model_display,
                exc,
            )
            return raw

        if not isinstance(payload, dict):
            logger.debug(
                "Structured output normalization skipped: payload is %s, not a dict (%s)",
                type(payload).__name__,
                model_display,
            )
            return raw

        normalized_fields = normalize_chunk_deep_payload_dict(payload)
        if not normalized_fields:
            return raw

        if logger.isEnabledFor(logging.DEBUG):
            # Second parse of ``raw`` avoids a deep copy of the mutated tree; ``raw`` is the
            # canonical pre-normalization snapshot (same as the initial ``json.loads`` source).
            payload_before = json.loads(raw)
            samples = chunk_deep_normalization_change_samples(
                payload_before, payload, max_items=5
            )
            sample_json = json.dumps(samples, ensure_ascii=True, default=str)
            if len(sample_json) > 800:
                sample_json = f"{sample_json[:800]}... [truncated]"
            logger.debug(
                "Normalized structured output fields (%s): %s; sample_changes=%s",
                model_display,
                ", ".join(normalized_fields),
                sample_json,
            )
        else:
            logger.debug(
                "Normalized structured output fields (%s): %s",
                model_display,
                ", ".join(normalized_fields),
            )
        return json.dumps(payload)

    @staticmethod
    def _is_repairable_structured_error(error: Exception) -> bool:
        """
        Return True when JSON repair heuristics are worth attempting.

        We only treat Pydantic ``ValidationError`` details that indicate the *payload*
        failed JSON decoding (not a mere schema field mismatch). Examples:
        - ``{"type": "json_invalid", ...}`` from ``model_validate_json`` on bad syntax.
        - ``msg`` containing ``eof while parsing`` (truncated JSON).
        - ``msg`` mentioning ``trailing comma`` (invalid JSON extension some models emit).
        """
        if not isinstance(error, ValidationError):
            return False
        for detail in error.errors():
            err_type = str(detail.get("type", ""))
            # Example: model_validate_json('{"a":') -> json_invalid
            if "json_invalid" in err_type:
                return True
            message = str(detail.get("msg", "")).lower()
            if "eof while parsing" in message or "trailing comma" in message:
                return True
        return False

    def _repair_structured_json_raw(
        self,
        *,
        raw: str,
        response_model: Type[BaseModel],
        model_display: str,
    ) -> str:
        """
        Repair ChunkDeepAnalysis JSON only; other response models are returned unchanged.

        Low-level parsing lives in :mod:`oasis.structured_output.json_repair`.
        """
        if not raw or not issubclass(response_model, ChunkDeepAnalysis):
            return raw
        return repair_chunk_deep_structured_json_raw(raw, model_display=model_display)

    @staticmethod
    def _build_safe_minimal_chunk_json(raw: str) -> Optional[str]:
        """
        Thin wrapper for tests; delegates to ``oasis.structured_output.json_repair``.

        Intended only for ChunkDeepAnalysis fallback payloads.
        """
        return build_safe_minimal_chunk_json(raw)

    def _log_structured_output_error(
        self,
        *,
        phase: str,
        response_model: Type[BaseModel],
        model_display: str,
        raw: str,
        error: Exception,
        file_path: Optional[str] = None,
        vuln_name: Optional[str] = None,
        chunk_index: Optional[int] = None,
        retry_attempt: Optional[int] = None,
        retry_max: Optional[int] = None,
    ) -> None:
        """
        Emit structured context for LLM JSON failures to error log files.
        """
        raw_text = raw or ""
        raw_preview = raw_text[:STRUCTURED_OUTPUT_RAW_PREVIEW_MAX_LEN]
        raw_truncated = len(raw_text) > STRUCTURED_OUTPUT_RAW_PREVIEW_MAX_LEN

        payload = {
            "event": "structured_output_error",
            "run_id": self.run_id,
            "phase": phase,
            "model": model_display,
            "response_model": response_model.__name__,
            "vulnerability": vuln_name,
            "file_path": file_path,
            "chunk_index": chunk_index,
            "error_type": error.__class__.__name__,
            "message": str(error),
            "retry_attempt": retry_attempt,
            "retry_max": retry_max,
            "raw_preview": raw_preview,
            "raw_truncated": raw_truncated,
        }
        logger.error("Structured output error context: %s", json.dumps(payload, ensure_ascii=True))

    def _is_retryable_structured_error(
        self,
        response_model: Type[BaseModel],
        error: Exception,
    ) -> bool:
        """Return True when the validation failure matches known transient JSON issues."""
        message = str(error)
        if issubclass(response_model, ScanVerdict):
            return "Field required" in message and "verdict" in message
        if issubclass(response_model, ChunkDeepAnalysis) and isinstance(error, ValidationError):
            for detail in error.errors():
                if validation_detail_is_exploitation_conditions_retryable(detail):
                    return True
        return "json_invalid" in message or "EOF while parsing" in message

    def _get_structured_retry_limit(self, response_model: Type[BaseModel]) -> int:
        """Bound retry count per structured model type."""
        return 2 if (
            issubclass(response_model, ScanVerdict)
            or issubclass(response_model, ChunkDeepAnalysis)
        ) else 1

    def _build_structured_retry_suffix(self, response_model: Type[BaseModel]) -> str:
        """Build minimal correction reminder appended to the prompt on retry."""
        if issubclass(response_model, ScanVerdict):
            return (
                "\n\nCORRECTION: Return EXACTLY one JSON object with one key only.\n"
                'Valid outputs: {"verdict":"SUSPICIOUS"} | {"verdict":"CLEAN"} | {"verdict":"ERROR"}.\n'
                "Do NOT output schema keys (description/properties/required/title/type).\n"
                "Do NOT use markdown code fences.\n"
            )
        if issubclass(response_model, ChunkDeepAnalysis):
            return chunk_deep_structured_retry_suffix()
        return generic_structured_retry_suffix()
        
    def _get_vulnerability_details(self, vulnerability: Union[str, Dict]) -> Tuple[str, str, list, str, str]:
        """
        Extract vulnerability details from dict or return empty strings if invalid.

        Args:
            vulnerability: Vulnerability to extract details from
            
        Returns:
            Tuple of (vulnerability name, description, patterns, impact, mitigation)
        """
        if isinstance(vulnerability, dict):
            return (vulnerability.get('name', ''), vulnerability.get('description', ''), vulnerability.get('patterns', []),
                    vulnerability.get('impact', ''), vulnerability.get('mitigation', ''))
        logger.error(f"Invalid vulnerability type: {vulnerability}")
        return "", "", [], "", ""

    def _build_analysis_prompt(
        self,
        vuln_name: str,
        vuln_desc: str,
        vuln_patterns: list,
        vuln_impact: str,
        vuln_mitigation: str,
        chunk_text: str,
        i: int,
        total_chunks: int,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """
        Construct the prompt for the LLM analysis.
        
        Args:
            vuln_name: Name of the vulnerability
            vuln_desc: Description of the vulnerability
            vuln_patterns: Common patterns associated with the vulnerability
            vuln_impact: Security impact of the vulnerability
            vuln_mitigation: Mitigation strategies for the vulnerability
            chunk_text: Code chunk to analyze
            i: Current chunk index
            total_chunks: Total number of chunks
            
        Returns:
            Formatted prompt for LLM analysis
        """
        # Format vulnerability info section
        vuln_info = (
            f"- Name: {vuln_name}\n"
            f"- Description: {vuln_desc}\n"
            f"- Common patterns: {', '.join(vuln_patterns[:5]) if vuln_patterns else 'N/A'}\n"
            f"- Security impact: {vuln_impact}\n"
            f"- Mitigation: {vuln_mitigation}"
        )
        
        common_prompt = _get_structured_deep_instructions(vuln_name)

        location_note = ""
        if start_line is not None and end_line is not None:
            location_note = (
                f"\nSOURCE LOCATION: This segment corresponds to lines {start_line}-{end_line} "
                f"(1-based, inclusive) in the file under analysis.\n"
            )

        return f"""{self.get_language_instruction()}You are a cybersecurity expert specialized in {vuln_name} vulnerabilities ONLY.

CRITICAL INSTRUCTION: You must ONLY analyze the code for {vuln_name} vulnerabilities.
DO NOT mention, describe, or analyze ANY other type of vulnerability.
If you find other security issues, IGNORE them completely.

VULNERABILITY DETAILS:
{vuln_info}
{location_note}
CODE SEGMENT TO ANALYZE:
```
{chunk_text}
```

YOUR TASK:
Analyze this code segment ({i + 1}/{total_chunks}) for {vuln_name} vulnerabilities ONLY.

{common_prompt}

{VULNERABILITY_PROMPT_EXTENSION}
"""

    def get_language_instruction(self) -> str:
        """
        Get the language instruction for the LLM analysis.
        """
        return f"You MUST write your response in {self.language['english_name']}. " if self.language_code != 'en' else ""

    def _analyze_code_chunk(
        self,
        prompt: str,
        file_path: str = None,
        chunk_text: str = None,
        vuln_name: str = None,
        mode: AnalysisMode = AnalysisMode.DEEP,
        ollama_json_format: Optional[dict] = None,
        response_model: Optional[Type[BaseModel]] = None,
        ollama_options: Optional[Dict[str, Any]] = None,
    ) -> str:
        """
        Analyze a single code chunk with the appropriate LLM based on mode.

        When ollama_json_format and response_model are set, uses Ollama structured outputs
        and returns: scan verdict as plain string, or model_dump_json() for structured models.

        ``ollama_options``, if provided, is merged into per-call defaults (timeout, structured
        deep ``num_predict``): keys from ``ollama_options`` override defaults; other default keys
        remain unless explicitly overridden.
        """
        model = self.scan_model if mode == AnalysisMode.SCAN else self.llm_model
        model_display = self.ollama_manager.get_model_display_name(model)

        if self.cache_manager.has_caching_info(file_path, chunk_text, vuln_name):
            if cached_result := self.cache_manager.get_cached_analysis(
                file_path, chunk_text, vuln_name, prompt, mode
            ):
                logger.debug(
                    f"Using cached {mode.value} analysis for chunk in {file_path} with {model_display}"
                )
                if getattr(self.args, "debug", False):
                    logger.debug(
                        "[LLM cache hit] mode=%s file=%s vuln=%s — skip network; cached result chars=%s",
                        mode.value,
                        file_path,
                        vuln_name,
                        len(cached_result) if isinstance(cached_result, str) else "?",
                    )
                return cached_result

        try:
            # Per-call Ollama defaults (timeout ms, structured deep num_predict); merge with
            # caller-supplied options so shared keys from the caller win and extras are kept.
            timeout = CHUNK_ANALYZE_TIMEOUT
            default_opts: Dict[str, Any] = {"timeout": timeout * 1000}
            if mode == AnalysisMode.DEEP and ollama_json_format is not None:
                default_opts["num_predict"] = CHUNK_DEEP_NUM_PREDICT
            opts: Dict[str, Any] = {**default_opts, **(ollama_options or {})}
            retry_limit = self._get_structured_retry_limit(response_model) if response_model is not None else 0
            effective_prompt = prompt

            logger.debug(f"Analyzing chunk with {model_display}")

            def persist_chunk_analysis_cache(payload: str) -> None:
                if self.cache_manager.has_caching_info(file_path, chunk_text, vuln_name):
                    self.cache_manager.store_analysis(
                        file_path, chunk_text, vuln_name, prompt, payload, mode
                    )

            result: Optional[str] = None
            chunk_cache_written = False

            for attempt in range(retry_limit + 1):
                if getattr(self.args, "debug", False):
                    llm_debug_log_request(
                        logger,
                        mode=mode.value,
                        model=model,
                        file_path=file_path,
                        vuln_name=vuln_name,
                        structured=ollama_json_format is not None,
                        attempt=attempt + 1,
                        prompt=effective_prompt,
                        full_content=True,
                    )
                chat_kwargs: dict = {
                    "model": model,
                    "messages": [{"role": "user", "content": effective_prompt}],
                    "options": opts,
                }
                if ollama_json_format is not None:
                    chat_kwargs["format"] = ollama_json_format

                response = self.ollama_manager.chat(**chat_kwargs)
                if not isinstance(response, dict):
                    logger.error(
                        "Ollama chat returned non-dict response type=%s repr=%r",
                        type(response).__name__,
                        response,
                    )
                    raise RuntimeError(f"Unexpected Ollama chat response type: {type(response).__name__}")
                if "message" not in response:
                    logger.error(
                        "Ollama chat response missing 'message' key; keys=%s preview=%s",
                        list(response.keys()),
                        str(response)[:800],
                    )
                    raise RuntimeError("Ollama chat response missing 'message'")
                msg = response["message"]
                if msg is None:
                    logger.error("Ollama chat response has null 'message'")
                    raise RuntimeError("Ollama chat response has null message")
                if not isinstance(msg, dict):
                    logger.error("Ollama 'message' is not a dict: type=%s", type(msg).__name__)
                    raise RuntimeError("Ollama chat message has invalid shape")
                if "content" not in msg:
                    logger.error("Ollama message missing 'content'; keys=%s", list(msg.keys()))
                    raise RuntimeError("Ollama message missing content field")
                raw = msg["content"]
                if raw is None:
                    logger.error("Ollama message content is null (file=%s vuln=%s)", file_path, vuln_name)
                    raise RuntimeError("Ollama message content is null")
                if not isinstance(raw, str):
                    raw = str(raw)
                if raw == "":
                    logger.warning(
                        "Ollama returned empty message.content (file=%s vuln=%s model=%s)",
                        file_path,
                        vuln_name,
                        model,
                    )
                    raise RuntimeError("Empty Ollama message content")
                if getattr(self.args, "debug", False):
                    llm_debug_log_response(
                        logger,
                        model=model,
                        file_path=file_path,
                        vuln_name=vuln_name,
                        raw_content=raw,
                        message=msg if isinstance(msg, dict) else None,
                        full_content=True,
                    )

                if (
                    response_model is not None
                    and issubclass(response_model, ChunkDeepAnalysis)
                    and structured_deep_raw_looks_degenerate(
                        raw, debug_log=getattr(self.args, "debug", False)
                    )
                ):
                    logger.warning(
                        "Degenerate structured deep output (repetitive or low-entropy JSON text), "
                        "file=%s vuln=%s attempt=%s/%s",
                        file_path,
                        vuln_name,
                        attempt + 1,
                        retry_limit + 1,
                    )
                    if attempt < retry_limit:
                        effective_prompt = effective_prompt + chunk_deep_degenerate_retry_suffix()
                        continue
                    result = self._resolve_structured_output_failure(
                        response_model=response_model,
                        raw=raw,
                        error=RuntimeError("degenerate structured output"),
                        model_display=model_display,
                    )
                    persist_chunk_analysis_cache(result)
                    chunk_cache_written = True
                    break

                if response_model is None:
                    result = raw
                    break

                try:
                    result = self._parse_structured_output_response(
                        raw=raw,
                        response_model=response_model,
                        model_display=model_display,
                        file_path=file_path,
                        vuln_name=vuln_name,
                        retry_attempt=attempt + 1,
                        retry_max=retry_limit,
                        raise_validation_error=True,
                    )
                    break
                except ValidationError as exc:
                    if attempt < retry_limit and self._is_retryable_structured_error(response_model, exc):
                        effective_prompt = effective_prompt + self._build_structured_retry_suffix(response_model)
                        continue
                    result = self._resolve_structured_output_failure(
                        response_model=response_model,
                        raw=raw,
                        error=exc,
                        model_display=model_display,
                    )
                    break

            if result is None:
                raise RuntimeError("Chunk analysis loop exited without a result (internal error).")
            if not chunk_cache_written:
                persist_chunk_analysis_cache(result)

            return result
        except Exception as e:
            logger.exception(f"Error during chunk analysis with {model_display}: {str(e)}")
            if response_model is not None:
                return self._resolve_structured_output_failure(
                    response_model=response_model,
                    raw="",
                    error=e,
                    model_display=model_display,
                )
            return f"Error during chunk analysis: {e}"

    def _build_scan_prompt(
        self,
        vuln_name: str,
        vuln_desc: str,
        chunk_text: str,
        start_line: Optional[int] = None,
        end_line: Optional[int] = None,
    ) -> str:
        """
        Build a simplified prompt for initial scanning with lightweight models
        
        Args:
            vuln_name: Name of the vulnerability to scan for
            vuln_desc: Brief description of the vulnerability
            chunk_text: Code chunk to analyze
            
        Returns:
            Simplified prompt optimized for lightweight models
        """
        location_note = ""
        if start_line is not None and end_line is not None:
            location_note = (
                f"\nSOURCE LOCATION: Lines {start_line}-{end_line} (1-based, inclusive) in the file.\n"
            )
        return f"""You are performing a preliminary security scan for {vuln_name} vulnerabilities.
Description of vulnerability: {vuln_desc}
{location_note}
IMPORTANT INSTRUCTIONS:
1. Analyze the code below for ONLY {vuln_name} vulnerabilities
2. Return EXACTLY one JSON object and nothing else.
3. The object must contain only one key: "verdict".
4. Allowed outputs are strictly:
   {{"verdict":"SUSPICIOUS"}}
   {{"verdict":"CLEAN"}}
   {{"verdict":"ERROR"}}
5. Do NOT include JSON Schema keys such as "description", "properties", "required", "title", or "type".
6. Do NOT use markdown code fences.
7. If your output is not valid JSON with exactly the key "verdict", regenerate before final answer.
8. Use verdict "SUSPICIOUS" if there might be ANY {vuln_name} vulnerabilities, otherwise "CLEAN".

Code to analyze:
```
{chunk_text}
```
"""

    def search_vulnerabilities(self, vulnerability: Union[str, Dict], threshold: float = DEFAULT_ARGS['THRESHOLD']) -> List[Tuple[str, float]]:
        """
        Search for potential vulnerabilities in the code base

        Args:
            vulnerability: Type of vulnerability to search for (string name or complete dict)
            threshold: Similarity threshold (default: 0.5)

        Returns:
            List of (identifier, similarity_score) tuples where identifier is either file_path or function_id
        """
        try:
            vuln_name = vulnerability['name']
            
            # Get embedding for vulnerability type using complete information if available
            vuln_vector = self.embedding_manager.get_vulnerability_embedding(vulnerability)
            if not vuln_vector:
                logger.error(f"Failed to get embedding for vulnerability type '{vuln_name}'. No embedding returned.")
                return []
                
            results = []
            
            # Process all files
            for file_path, data in self.code_base.items():
                if self.analyze_by_function:
                    # Process functions for this file
                    self._process_functions(file_path, data, vuln_vector, threshold, results)
                else:
                    # Process file as a whole
                    self._process_file(file_path, data, vuln_vector, threshold, results)
                    
            # Sort by similarity score in descending order
            return sorted(results, key=lambda x: x[1], reverse=True)
                
        except Exception as e:
            logger.exception(f"Error during vulnerability search: {str(e)}")
            return []

    def process_analysis_with_model(self, vulnerabilities, args, report: Report):
        """
        Process vulnerability analysis via the LangGraph orchestrator (canonical pipeline).

        Older adaptive / standard-vs-deep orchestration paths were removed; this entry point must
        stay LangGraph-only—do not add alternate pipelines here (avoids drift and double maintenance).

        Args:
            vulnerabilities: List of vulnerability types to analyze
            args: Command line arguments
            report: Report object

        Returns:
            Dictionary with analysis results
        """
        from .agent.invoke import invoke_oasis_langgraph

        all_results = invoke_oasis_langgraph(self, vulnerabilities, args, report)
        langgraph_emit_post_pipeline(logger)
        logger.info("GENERATING FINAL REPORT")
        nv_final = len(vulnerabilities)
        _publish_exec_summary_progress(
            self,
            report,
            all_results,
            completed_vulnerabilities=nv_final,
            total_vulnerabilities=nv_final,
            current_vulnerability=None,
            tested_vulnerabilities=list(all_results.keys()),
            **graph_final_phases(self, nv_final, updated_at=progress_timestamp_iso()),
        )
        return all_results

    # LangGraph stage entry points: time/LLM budgets and PoC sizes are mostly in
    # ``oasis.config`` (e.g. ``CHUNK_*``, ``CONTEXT_EXPAND_*``, ``POC_*``) and
    # ``oasis.helpers.poc``; keep those in sync when tuning pipeline behavior.

    def langgraph_discover_and_publish(
        self, vulnerabilities: List[Dict[str, Any]], args: Any, report: Optional[Report]
    ) -> Dict[str, Any]:
        nv = len(vulnerabilities)
        tasks: List[Dict[str, Any]] = []
        for vuln in vulnerabilities:
            tasks.extend(
                {
                    "file_path": path,
                    "vuln": vuln,
                    "similarity_score": score,
                }
                for path, score in self.search_vulnerabilities(
                    vuln, threshold=args.threshold
                )
                if score >= args.threshold and path in self.code_base
            )
        if report is not None:
            n_files = safe_code_base_file_count(self)
            phases = graph_phases_discover_done_scan_pending(n_files, nv)
            _langgraph_publish_mid_pipeline(self, report, nv=nv, phases=phases)
        return {"embedding_tasks": tasks}

    def langgraph_scan_and_publish(
        self, embedding_tasks: List[Dict[str, Any]], args: Any, report: Optional[Report]
    ) -> Dict[str, Any]:
        task_list = list(embedding_tasks or [])
        all_suspicious_data: Dict[Tuple[str, str], Dict[str, Any]] = {}
        suspicious_files_by_vuln: Dict[str, Any] = {}
        nv = embedding_tasks_vuln_types_total(task_list)
        n_files = safe_code_base_file_count(self)

        def _run_one_task(t: Dict[str, Any]) -> None:
            file_path = t["file_path"]
            vuln = t["vuln"]
            similarity_score = t["similarity_score"]
            vuln_details = self._get_vulnerability_details(vuln)
            vuln_name = vuln_details[0]
            suspicious_chunks = self._scan_file_for_vulnerability(
                file_path, vuln, vuln_details, similarity_score, args.silent
            )
            if not suspicious_chunks:
                return
            key = (file_path, vuln_name)
            all_suspicious_data[key] = {
                "chunks": suspicious_chunks,
                "vuln_data": vuln,
                "similarity_score": similarity_score,
            }

        if task_list:
            with tqdm(
                                total=len(task_list),
                                desc="LangGraph scan tasks (file×vuln)",
                                position=1,
                                leave=True,
                                disable=getattr(args, "silent", False),
                            ) as scan_tasks_pbar:
                for t in task_list:
                    short = Path(t["file_path"]).name
                    if len(short) > 30:
                        short = f"{short[:27]}..."
                    v_obj = t.get("vuln") or {}
                    vn = v_obj.get("name") or v_obj.get("tag") or "?"
                    vn_display = vn if len(vn) <= 48 else f"{vn[:45]}..."
                    scan_tasks_pbar.set_postfix_str(vn_display)
                    t_scan = time_module.monotonic()
                    if getattr(args, "debug", False):
                        langgraph_emit(
                            logger,
                            logging.DEBUG,
                            LG_DEBUG_SEPARATOR,
                            separator_file_scope(short, f"vuln={vn}"),
                            pbar=scan_tasks_pbar,
                        )
                    _run_one_task(t)
                    dt = time_module.monotonic() - t_scan
                    langgraph_emit(
                        logger,
                        logging.INFO,
                        LG_SCAN_TASK_COMPLETE,
                        cli_bold(short),
                        cli_bold(vn),
                        dt,
                        pbar=scan_tasks_pbar,
                    )
                    scan_tasks_pbar.update(1)
                # Blank line between last Task done text and tqdm bar redraw (still inside tqdm context).
                if not getattr(scan_tasks_pbar, "disable", True):
                    tqdm.write("", file=sys.stderr)
            if not getattr(args, "silent", False):
                sys.stderr.write("\n")
        for key, data in all_suspicious_data.items():
            fp, vn = key
            if vn not in suspicious_files_by_vuln:
                suspicious_files_by_vuln[vn] = {"files": [], "vuln_data": data["vuln_data"]}
            suspicious_files_by_vuln[vn]["files"].append((fp, data["similarity_score"]))

        if report is not None:
            phases = graph_phases_scan_done_expand_pending(n_files, nv)
            _langgraph_publish_mid_pipeline(self, report, nv=nv, phases=phases)
        payload = {"suspicious_data": all_suspicious_data, "files_by_vuln": suspicious_files_by_vuln}
        return {"suspicious_payload": payload}

    def langgraph_expand_and_publish(
        self,
        suspicious_payload: Dict[str, Any],
        args: Any,
        current_iteration: int,
        verify_retry_pending: bool,
    ) -> Dict[str, Any]:
        it = current_iteration + (1 if verify_retry_pending else 0)
        # Padding grows with expand iteration; baseline matches ``OASIS_CONTEXT_EXPAND_PADDING_*`` defaults (40).
        padding = 40 + 20 * max(0, it)
        suspicious_data = suspicious_payload.get("suspicious_data") or {}
        new_data: Dict[Tuple[str, str], Dict[str, Any]] = {}
        for key, data in suspicious_data.items():
            file_path, _vn = key
            if file_path not in self.code_base:
                new_data[key] = data
                continue
            content = self.code_base[file_path]["content"]
            expanded = expand_suspicious_chunk_records(
                content,
                data["chunks"],
                padding_before=padding,
                padding_after=padding,
                max_chars=CONTEXT_EXPAND_MAX_CHARS,
            )
            new_data[key] = {**data, "chunks": expanded}
        out = {**suspicious_payload, "suspicious_data": new_data}
        return {"suspicious_payload": out, "expand_iterations": it, "verify_retry_pending": False}

    def langgraph_deep_and_publish(
        self,
        suspicious_payload: Dict[str, Any],
        args: Any,
        report: Report,
        *,
        graph_deep_pass: int = 0,
    ) -> Dict[str, Any]:
        nv = deep_payload_vuln_types_total(suspicious_payload.get("files_by_vuln"))
        all_results = self._perform_deep_analysis(
            suspicious_payload,
            args,
            report,
            None,
            n_vuln_types=nv,
            graph_progress=True,
            graph_deep_pass=graph_deep_pass,
        )
        return {"all_results": all_results}

    def langgraph_verify(
        self, all_results: Dict[str, Any], args: Any, expand_it: int, max_it: int
    ) -> Dict[str, Any]:
        errors = 0
        for _vn, rows in (all_results or {}).items():
            if not isinstance(rows, list):
                continue
            for row in rows:
                for ch in row.get("structured_chunks") or []:
                    if isinstance(ch, dict) and ch.get("validation_error"):
                        errors += 1
        retry = errors > 0 and expand_it < max_it
        return {"verify_retry_pending": retry, "validation_error_count": errors}

    def langgraph_finalize_reports(
        self,
        vulnerabilities: List[Dict[str, Any]],
        args: Any,
        report: Report,
        all_results: Dict[str, Any],
    ) -> Dict[str, Any]:
        _ = (vulnerabilities, args, report)
        return {"all_results": all_results}

    def _build_poc_assist_llm_section(self, args: Any, all_results: Dict[str, Any]) -> str:
        compact = build_compact_findings_digest(all_results)
        if not compact:
            return (
                "## LLM-assisted executable PoC\n\n"
                "_No structured findings available to derive a PoC._"
            )
        digest = finalize_poc_digest_json(compact, POC_DIGEST_JSON_MAX_CHARS)
        prompt = f"""You are assisting a defensive security review.

Based ONLY on the JSON summary below (from a prior static scan), produce:
1) A minimal standalone proof-of-concept: a short script OR shell/Python/etc. commands that could demonstrate the issue in an isolated lab or VM.
2) Prefer the language implied by file paths and code snippets when obvious.
3) Start with one short safety paragraph: local sandbox only, authorized testing, no third-party targets.

OASIS will LOG your answer only; it will NOT execute your output. The human must review and run any code manually.

FINDINGS SUMMARY (valid JSON envelope; ``truncated_for_llm_prompt_budget`` may be true):
{digest}
"""
        try:
            opts: dict = poc_assist_chat_options()
            if getattr(args, "debug", False):
                llm_debug_log_request(
                    logger,
                    mode="poc_assist",
                    model=self.llm_model,
                    file_path=None,
                    vuln_name=None,
                    structured=False,
                    attempt=1,
                    prompt=prompt,
                    full_content=False,
                )
            response = self.ollama_manager.chat(
                model=self.llm_model,
                messages=[{"role": "user", "content": prompt}],
                options=opts,
            )
            msg = response.get("message") or {}
            raw = msg.get("content") or ""
            if getattr(args, "debug", False):
                llm_debug_log_response(
                    logger,
                    model=self.llm_model,
                    file_path=None,
                    vuln_name=None,
                    raw_content=raw,
                    message=msg if isinstance(msg, dict) else None,
                    full_content=False,
                )
        except Exception:
            logger.exception("Executable PoC generation failed")
            return (
                "## LLM-assisted executable PoC\n\n"
                "_PoC generation failed. Run with **`--debug`** (`-d`) for diagnostic logs "
                "(details are not shown in reports to avoid leaking internal errors)._"
            )

        model_display = self.ollama_manager.get_model_display_name(self.llm_model)
        body = raw.strip() or "_Empty model response._"
        return (
            "## LLM-assisted executable PoC\n\n"
            f"_Generated by **{model_display}** for manual review in a sandbox; "
            f"OASIS does not execute this output._\n\n"
            f"{body}"
        )

    def langgraph_poc_assist(self, args: Any, all_results: Dict[str, Any]) -> Dict[str, Any]:
        poc_hints = bool(getattr(args, "poc_hints", False))
        poc_assist = bool(getattr(args, "poc_assist", False))
        if not poc_hints and not poc_assist:
            return {"poc_hints_markdown": ""}

        parts: List[str] = []
        if poc_hints:
            parts.append(build_poc_hints_markdown(all_results))
        if poc_assist:
            parts.append(self._build_poc_assist_llm_section(args, all_results))

        text = "\n\n".join(p for p in parts if p)
        maybe_debug_log_poc_stage_output(logger, args, text)
        return {"poc_hints_markdown": text}

    def _scan_file_for_vulnerability(self, file_path, vuln, vuln_details, similarity_score, silent=False):
        """
        Scan a file for a specific vulnerability using lightweight model
        
        Args:
            file_path: Path to the file to scan
            vuln: Vulnerability data
            vuln_details: Extracted vulnerability details tuple
            similarity_score: Similarity score from embedding comparison
            silent: Whether to disable progress bars
            
        Returns:
            List of suspicious chunks in the file
        """
        vuln_name, vuln_desc, _, _, _ = vuln_details
        
        # Get the file content and chunk it (with 1-based line spans per chunk)
        code = self.code_base[file_path]["content"]
        spanned = chunk_content_with_spans(code, MAX_CHUNK_SIZE)
        code_chunks = [t[0] for t in spanned]

        # Initialize suspicious chunks for this file
        suspicious_chunks = []

        # Scan each chunk with the lightweight model
        with tqdm(
            total=len(code_chunks),
            desc=f"Chunks in {Path(file_path).name}",
            position=3,
            leave=False,
            disable=silent,
        ) as chunk_pbar:
            for i, (chunk, start_line, end_line) in enumerate(spanned):
                # Use a simplified prompt for the scanning phase
                scan_prompt = self._build_scan_prompt(
                    vuln_name, vuln_desc, chunk, start_line=start_line, end_line=end_line
                )
                scan_result = self._analyze_code_chunk(
                    scan_prompt,
                    file_path,
                    chunk,
                    vuln_name,
                    mode=AnalysisMode.SCAN,
                    ollama_json_format=ScanVerdict.model_json_schema(),
                    response_model=ScanVerdict,
                )

                scan_verdict = str(scan_result).strip().upper() if scan_result is not None else ""
                if not scan_verdict:
                    logger.warning(
                        f"Empty structured scan verdict for chunk {i + 1} in {file_path}; treating as ERROR"
                    )
                    scan_verdict = "ERROR"
                if scan_verdict == "SUSPICIOUS":
                    suspicious_chunks.append((i, chunk, start_line, end_line))
                elif scan_verdict == "ERROR":
                    logger.warning(
                        f"Structured scan verdict validation failed for chunk {i + 1} in {file_path}; continuing"
                    )
                elif scan_verdict == "CLEAN":
                    logger.debug(
                        f"Structured scan verdict CLEAN for chunk {i + 1} in {file_path}"
                    )
                else:
                    logger.warning(
                        f"Unexpected structured scan verdict '{scan_verdict}' for chunk {i + 1} in {file_path}; treating as CLEAN"
                    )
                    
                chunk_pbar.update(1)
        
        # Store indices for potential future use
        self.suspicious_sections[(file_path, vuln_name)] = [idx for idx, *_ in suspicious_chunks]
        
        return suspicious_chunks

    def _deep_phase_progress_payload(
        self,
        *,
        n_files: int,
        vuln_types_total: int,
        deep_completed: int,
        graph_progress: bool,
    ) -> Dict[str, Any]:
        """Executive-summary extras during deep analysis (graph pipeline vs legacy standard layout)."""
        if graph_progress:
            nv = vuln_types_total
            phases = graph_phases_deep_in_progress(
                n_files,
                vuln_types_total,
                deep_completed=deep_completed,
            )
            return graph_progress_extras(analyzer=self, nv=nv, phases=phases)
        return standard_deep_phase_extras(
            n_files,
            vuln_types_total,
            deep_completed=deep_completed,
        )
    
    def _perform_deep_analysis(
        self,
        suspicious_data,
        args,
        report,
        main_pbar=None,
        *,
        n_vuln_types: Optional[int] = None,
        graph_progress: bool = False,
        graph_deep_pass: int = 0,
    ):
        """
        Perform deep analysis on all suspicious chunks using powerful model
        
        Args:
            suspicious_data: Data from initial scanning phase
            args: Command-line arguments
            report: Report object
            main_pbar: Optional main progress bar to update
            n_vuln_types: Vulnerability-type denominator for progress (defaults to files_by_vuln size)
            graph_progress: Use LangGraph phase rows for incremental summary progress
            graph_deep_pass: LangGraph ``expand_iterations`` when entering deep (0 = first pass)
            
        Returns:
            Dictionary with analysis results for all vulnerabilities
        """
        langgraph_emit(
            logger,
            logging.INFO,
            LG_LLM_SELECTED,
            cli_bold(self.ollama_manager.get_model_display_name(self.llm_model)),
        )
        if not getattr(args, "silent", False):
            tqdm.write("", file=sys.stderr)

        all_suspicious_chunks = suspicious_data['suspicious_data']
        suspicious_files_by_vuln = suspicious_data['files_by_vuln']
        vuln_types_total = (
            n_vuln_types if n_vuln_types is not None else len(suspicious_files_by_vuln)
        )
        n_files = safe_code_base_file_count(self)

        reset_tqdm_phase_bar(
            main_pbar,
            total=vuln_types_total,
            description="Overall vulnerability progress",
        )

        _publish_exec_summary_progress(
            self,
            report,
            {},
            completed_vulnerabilities=0,
            total_vulnerabilities=vuln_types_total,
            current_vulnerability=None,
            tested_vulnerabilities=[],
            **self._deep_phase_progress_payload(
                n_files=n_files,
                vuln_types_total=vuln_types_total,
                deep_completed=0,
                graph_progress=graph_progress,
            ),
        )

        # Dictionary to store results for all vulnerabilities
        all_results = {}
        
        # Process each vulnerability separately for reporting
        with tqdm(total=vuln_types_total, desc="Vulnerabilities analyzed (deep analysis)",
                 position=1, leave=False, disable=args.silent) as deep_vuln_pbar:
            for completed_count, (vuln_name, data) in enumerate(suspicious_files_by_vuln.items(), start=1):
                vuln = data['vuln_data']

                # Update main progress bar before starting the deep analysis
                if main_pbar:
                    main_pbar.set_postfix_str(f"Analyzing: {vuln_name}")

                if getattr(args, "debug", False):
                    langgraph_emit(
                        logger,
                        logging.DEBUG,
                        LG_DEBUG_SEPARATOR,
                        separator_vulnerability(vuln_name),
                        pbar=deep_vuln_pbar,
                    )
                t_deep_vuln = time_module.monotonic()

                _publish_exec_summary_progress(
                    self,
                    report,
                    all_results,
                    completed_vulnerabilities=completed_count - 1,
                    total_vulnerabilities=vuln_types_total,
                    current_vulnerability=vuln_name,
                    tested_vulnerabilities=list(all_results.keys()),
                    **self._deep_phase_progress_payload(
                        n_files=n_files,
                        vuln_types_total=vuln_types_total,
                        deep_completed=max(0, completed_count - 1),
                        graph_progress=graph_progress,
                    ),
                )

                detailed_results = self._analyze_vulnerability_deep(vuln, vuln_name, all_suspicious_chunks, args.silent)

                dt_vuln = time_module.monotonic() - t_deep_vuln
                langgraph_emit(
                    logger,
                    logging.INFO,
                    LG_DEEP_VULN_FINISHED,
                    cli_bold(vuln_name),
                    dt_vuln,
                    pbar=deep_vuln_pbar,
                )

                # Store results for this vulnerability
                all_results[vuln_name] = detailed_results

                # Generate vulnerability report
                if detailed_results:
                    report.generate_vulnerability_report(
                        vulnerability=vuln,
                        results=detailed_results,
                        model_name=self.llm_model,
                    )
                else:
                    logger.info(f"No suspicious code found for {cli_bold(vuln_name)}")

                _publish_exec_summary_progress(
                    self,
                    report,
                    all_results,
                    completed_vulnerabilities=completed_count,
                    total_vulnerabilities=vuln_types_total,
                    current_vulnerability=None,
                    tested_vulnerabilities=list(all_results.keys()),
                    **self._deep_phase_progress_payload(
                        n_files=n_files,
                        vuln_types_total=vuln_types_total,
                        deep_completed=completed_count,
                        graph_progress=graph_progress,
                    ),
                )

                # Update progress bars
                deep_vuln_pbar.update(1)
                if main_pbar:
                    main_pbar.update(1)

        return all_results
    
    def _analyze_vulnerability_deep(self, vuln, vuln_name, all_suspicious_chunks, silent=False):
        """
        Perform deep analysis for a specific vulnerability across all files
        
        Args:
            vuln: Vulnerability data
            vuln_name: Name of the vulnerability
            all_suspicious_chunks: Dictionary with suspicious chunks data
            silent: Whether to disable progress bars
            
        Returns:
            List of detailed results for this vulnerability
        """
        deep_results = []

        # Get all files with suspicious chunks for this vulnerability
        suspicious_files = [file_path for (file_path, vname), _ in all_suspicious_chunks.items() 
                          if vname == vuln_name]

        if not suspicious_files:
            logger.info(f"No suspicious chunks found for {vuln_name}")
            return []

        logger.debug(f"\nAnalyzing {len(suspicious_files)} files with suspicious chunks for {vuln_name}")

        # Progress bar for files being analyzed
        with tqdm(total=len(suspicious_files), desc=f"Analyzing files for {vuln_name}", 
                 position=2, leave=False, disable=silent) as file_pbar:
            # Analyze all suspicious files for this vulnerability
            for file_path in suspicious_files:
                key = (file_path, vuln_name)
                suspicious_data = all_suspicious_chunks[key]

                if getattr(self.args, "debug", False):
                    logger.debug(separator_file_scope(Path(file_path).name))

                if file_result := self._analyze_file_suspicious_chunks(
                    file_path, suspicious_data, vuln, silent
                ):
                    deep_results.append(file_result)

                file_pbar.update(1)

        return deep_results
    
    def _analyze_file_suspicious_chunks(self, file_path, suspicious_data, vuln, silent=False):
        """
        Analyze suspicious chunks in a specific file for a vulnerability
        
        Args:
            file_path: Path to the file
            suspicious_data: Data about suspicious chunks in this file
            vuln: Vulnerability data
            silent: Whether to disable progress bars
            
        Returns:
            Detailed analysis result for this file
        """
        suspicious_chunks = suspicious_data['chunks']
        similarity_score = suspicious_data['similarity_score']

        vuln_name, vuln_desc, vuln_patterns, vuln_impact, vuln_mitigation = self._get_vulnerability_details(vuln)

        # Perform deep analysis on suspicious chunks
        analyses = []
        with tqdm(total=len(suspicious_chunks), 
                 desc=f"Chunks in {Path(file_path).name}", 
                 position=3, leave=False, disable=silent) as chunk_pbar:
            for chunk_idx, chunk, start_line, end_line in suspicious_chunks:
                # Build a detailed prompt for deep analysis
                prompt = self._build_analysis_prompt(
                    vuln_name,
                    vuln_desc,
                    vuln_patterns,
                    vuln_impact,
                    vuln_mitigation,
                    chunk,
                    chunk_idx,
                    len(suspicious_chunks),
                    start_line=start_line,
                    end_line=end_line,
                )

                # Analyze with the deep model
                analysis_result = self._analyze_code_chunk(
                    prompt,
                    file_path,
                    chunk,
                    vuln_name,
                    mode=AnalysisMode.DEEP,
                    ollama_json_format=ChunkDeepAnalysis.model_json_schema(),
                    response_model=ChunkDeepAnalysis,
                )
                try:
                    validated = ChunkDeepAnalysis.model_validate_json(analysis_result)
                    merged = validated.model_copy(
                        update={"start_line": start_line, "end_line": end_line}
                    )
                    analyses.append(
                        _enrich_findings_with_snippet_file_lines(merged, chunk, start_line)
                    )
                except ValidationError as exc:
                    self._log_structured_output_error(
                        phase="deep",
                        response_model=ChunkDeepAnalysis,
                        model_display=self.ollama_manager.get_model_display_name(self.llm_model),
                        raw=analysis_result,
                        error=exc,
                        file_path=file_path,
                        vuln_name=vuln_name,
                        chunk_index=chunk_idx,
                    )
                    analyses.append(
                        ChunkDeepAnalysis(
                            findings=[],
                            notes=f"Invalid chunk JSON: {analysis_result[:500]}",
                            start_line=start_line,
                            end_line=end_line,
                        )
                    )
                chunk_pbar.update(1)

        if not analyses:
            return None

        combined_analysis = "\n\n<div class=\"page-break\"></div>\n\n".join(
            chunk_analysis_to_markdown(c, idx) for idx, c in enumerate(analyses)
        )

        return {
            'file_path': file_path,
            'similarity_score': similarity_score,
            'analysis': combined_analysis,
            'structured_chunks': [c.model_dump() for c in analyses],
            'vulnerability': {
                'name': vuln_name,
                'description': vuln_desc,
                'impact': vuln_impact,
                'mitigation': vuln_mitigation
            }
        }
    
    @staticmethod
    def get_vulnerabilities_to_check(args, vuln_mapping):
        """
        Determine which vulnerabilities to check based on args
        
        Args:
            args: Command line arguments
            vuln_mapping: Dictionary mapping vulnerability tags to definitions
            
        Returns:
            Tuple of (vulnerability_list, invalid_tags)
        """
        if args.vulns.lower() == 'all':
            return list(vuln_mapping.values()), None

        selected_tags = [tag.strip() for tag in args.vulns.split(',')]
        if invalid_tags := [
            tag for tag in selected_tags if tag not in vuln_mapping
        ]:
            logger.error(f"Invalid vulnerability tags: {', '.join(invalid_tags)}")
            logger.error("Use --help to see available tags")
            return None, invalid_tags

        return [vuln_mapping[tag] for tag in selected_tags], None

    def _process_functions(self, file_path: str, data: Dict, vuln_vector: List[float], 
                          threshold: float, results: List[Tuple[str, float]]) -> None:
        """
        Process functions in a file

        Args:
            file_path: Path to the file to process
            data: Data to process
            vuln_vector: Vulnerability vector to compare against
            threshold: Similarity threshold
            results: List to store results
        """
        if 'functions' not in data:
            return
            
        for func_id, func_data in data['functions'].items():
            if not func_data.get('embedding'):
                continue
                
            try:
                similarity = calculate_similarity(vuln_vector, func_data['embedding'])
                if similarity >= threshold:
                    results.append((func_id, similarity))
            except Exception as e:
                logger.exception(f"Error processing function {func_id}: {str(e)}")
                
    def _process_file(self, file_path: str, data: Dict, vuln_vector: List[float], 
                     threshold: float, results: List[Tuple[str, float]]) -> None:
        """
        Process entire file

        Args:
            file_path: Path to the file to process
            data: Data to process
            vuln_vector: Vulnerability vector to compare against
            threshold: Similarity threshold
            results: List to store results
        """
        try:
            # Extract embedding based on its structure
            file_vectors = self._extract_file_vectors(data)
            if not file_vectors:
                return
                
            # For multiple chunks, find the highest similarity
            if isinstance(file_vectors, list) and isinstance(file_vectors[0], list):
                highest_similarity = max(calculate_similarity(vuln_vector, vec) for vec in file_vectors)
                if highest_similarity >= threshold:
                    results.append((file_path, highest_similarity))
            else:
                # Single vector
                similarity = calculate_similarity(vuln_vector, file_vectors)
                if similarity >= threshold:
                    results.append((file_path, similarity))
        except Exception as e:
            logger.exception(f"Error processing file {file_path}: {str(e)}")
            
    def _extract_file_vectors(self, data: Dict) -> Union[List[float], List[List[float]], None]:
        """
        Extract embedding vectors from file data

        Args:
            data: Data to extract vectors from
            
        Returns:
            Embedding vectors or None if not available
        """
        embedding = data.get('embedding')
        if not embedding:
            return None
            
        if isinstance(embedding, dict):
            return embedding.get('embedding')
        elif isinstance(embedding, list) and all(isinstance(item, list) for item in embedding):
            return embedding  # Chunked embeddings
        else:
            return embedding  # Single embedding vector

class EmbeddingAnalyzer:
    """
    Class for analyzing embeddings against vulnerability types

    Args:
        embedding_manager: Initialized EmbeddingManager
    """
    
    def __init__(self, embedding_manager: EmbeddingManager, ollama_manager: OllamaManager):
        """
        Initialize the embedding analyzer
        
        Args:
            embedding_manager: Initialized EmbeddingManager
        """
        self.ollama_manager = ollama_manager
        self.embedding_manager = embedding_manager
        self.code_base = embedding_manager.code_base
        self.embedding_model = embedding_manager.embedding_model
        self.results_cache = {}  # Cache for results by vulnerability type
        self.embedding_analysis_type = embedding_manager.embedding_analysis_type
        self.analyze_by_function = embedding_manager.analyze_by_function
        self.silent = bool(getattr(embedding_manager, "silent", False))

    def analyze_vulnerability(self, vuln: Dict) -> List[Dict[str, Any]]:
        """
        Analyze a single vulnerability type.

        Args:
            vuln: Vulnerability to analyze
        """

        cache_key = (
            f"{sanitize_name(vuln['name'])}_{self.embedding_manager.embedding_analysis_type}"
        )
        if cache_key in self.results_cache:
            return self.results_cache[cache_key]

        logger.info(f"🚨 Analyzing vulnerability: {vuln['name']}")

        process_args = self._prepare_analysis_args(vuln)
        results = self._execute_parallel_analysis(process_args)

        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        self.results_cache[cache_key] = results
        return results
    
    def generate_threshold_analysis(self, results: List[Dict], thresholds: List[float] = None) -> List[Dict]:
        """
        Generate threshold analysis for results
        
        Args:
            results: List of result dictionaries
            thresholds: List of thresholds to analyze
            
        Returns:
            List of dictionaries with threshold analysis
        """
        if not thresholds:
            thresholds = EMBEDDING_THRESHOLDS
            
        threshold_analysis = []
        
        total_items = len(results)
        if total_items == 0:
            return []
            
        for threshold in thresholds:
            matching_items = sum(r['similarity_score'] >= threshold for r in results)
            percentage = (matching_items / total_items) * 100
            
            threshold_analysis.append({
                'threshold': threshold,
                'matching_items': matching_items,
                'percentage': percentage
            })
            
        return threshold_analysis
    
    def calculate_statistics(self, results: List[Dict]) -> Dict[str, float]:
        """
        Calculate statistics for results
        
        Args:
            results: List of result dictionaries
            
        Returns:
            Dictionary with statistics
        """
        if not results:
            return {
                'avg_score': 0,
                'median_score': 0,
                'max_score': 0,
                'min_score': 0
            }
            
        scores = [r['similarity_score'] for r in results]
        
        return {
            'avg_score': sum(scores) / len(scores),
            'median_score': sorted(scores)[len(scores)//2],
            'max_score': max(scores),
            'min_score': min(scores),
            'count': len(scores)
        }
    
    def analyze_all_vulnerabilities(self, vulnerabilities: List[Dict], 
                                   thresholds: List[float] = None,
                                   console_output: bool = True) -> Dict[str, Dict]:
        """
        Analyze all vulnerability types
        
        Args:
            vulnerabilities: List of vulnerabilities
            thresholds: List of thresholds
            console_output: Whether to print results to console
            
        Returns:
            Dictionary with results for all vulnerabilities
        """
        all_results = {}

        if console_output:
            logger.info("\nEmbeddings Distribution Analysis")
            logger.info("===================================\n")

        # Analyze each vulnerability
        for vuln in vulnerabilities:
            vuln_name = vuln['name']

            # Get results for this vulnerability
            results = self.analyze_vulnerability(vuln)

            # Generate threshold analysis
            threshold_analysis = self.generate_threshold_analysis(results, thresholds)

            # Calculate statistics
            statistics = self.calculate_statistics(results)

            # Store in all_results
            all_results[vuln_name] = {
                'results': results,
                'threshold_analysis': threshold_analysis,
                'statistics': statistics
            }

            # Console output if requested
            if console_output:
                self._print_vulnerability_analysis(vuln_name, results, threshold_analysis, statistics)

        return all_results

    def generate_vulnerability_statistics(self, all_results: Dict[str, Dict]) -> List[Dict]:
        """
        Generate vulnerability statistics for all results
        
        Args:
            all_results: Dictionary with results for all vulnerabilities
            
        Returns:
            List of dictionaries with vulnerability statistics
        """
        vuln_stats = []
        
        total_high = 0
        total_medium = 0
        total_low = 0
        total_items = 0
        
        for vuln_type, data in all_results.items():
            results = data['results']
            
            high = sum(r['similarity_score'] >= 0.8 for r in results)
            medium = sum(0.6 <= r['similarity_score'] < 0.8 for r in results)
            low = sum(0.4 <= r['similarity_score'] < 0.6 for r in results)
            total = len(results)
            
            total_high += high
            total_medium += medium
            total_low += low
            total_items += total
            
            if total > 0:
                vuln_stats.append({
                    'name': vuln_type,
                    'total': total,
                    'high': high,
                    'medium': medium,
                    'low': low
                })
        
        # Add totals
        vuln_stats.append({
            'name': 'TOTAL',
            'total': total_items,
            'high': total_high,
            'medium': total_medium,
            'low': total_low,
            'is_total': True
        })
        
        return vuln_stats

    def _prepare_analysis_args(self, vuln: Dict) -> list:
        """
        Prepare arguments for parallel processing.

        Args:
            vuln: Dictionary containing vulnerability information
            
        Returns:
            List of processed arguments
        """
        
        # Initialize the list once
        process_args = []

        # Common parameters for all arguments
        common_args = {
            "vulnerability": vuln,
            "embedding_model": self.embedding_model,
            "api_url": self.ollama_manager.api_url
        }
        
        # Process each element based on analysis mode
        for file_path, data in self.code_base.items():
            if self.analyze_by_function:
                if 'functions' in data:
                    # Process each function individually
                    for func_id, func_data in data['functions'].items():
                        if func_data.get('embedding'):
                            args = {
                                "item_id": func_id,
                                "data": func_data,
                                "is_function": True,
                                **common_args
                            }
                            process_args.append(argparse.Namespace(**args))
            elif data.get('embedding'):
                # Process the entire file
                args = {
                    "item_id": file_path,
                    "data": data,
                    "is_function": False,
                    **common_args
                }
                process_args.append(argparse.Namespace(**args))
        
        return process_args

    def _execute_parallel_analysis(self, process_args: list) -> list:
        """
        Execute analysis in parallel and collect results.

        Args:
            process_args: List of processed arguments
            
        Returns:
            List of analysis results
        """

        num_processes = max(1, min(cpu_count(), len(process_args)))
        results = []
        with tqdm(
            total=len(process_args),
            desc="Analyzing",
            leave=True,
            disable=self.silent,
        ) as pbar:
            with Pool(processes=num_processes) as pool:
                for result in pool.imap(analyze_item_parallel, process_args):
                    if result and 'error' not in result:
                        results.append(result)
                    pbar.update(1)
        return results

    def _print_vulnerability_analysis(self, vuln_name: str, results: List[Dict], 
                                     threshold_analysis: List[Dict], statistics: Dict):
        """
        Print vulnerability analysis to console
        
        Args:
            vuln_name: Name of the vulnerability
            results: List of result dictionaries
            threshold_analysis: List of threshold analysis dictionaries
            statistics: Dictionary with statistics
        """
        logger.info(f"\nAnalyzing: {vuln_name}")
        logger.info("-" * (14 + len(vuln_name)))
        
        # Print threshold analysis
        logger.info("\nThreshold Analysis:")
        logger.info("----------------------")
        for analysis in threshold_analysis:
            threshold = analysis['threshold']
            matching_items = analysis['matching_items']
            percentage = analysis['percentage']
            logger.info(f"Threshold {threshold:.1f}: {matching_items:3d} items ({percentage:5.1f}%)")
        
        # Print top 5 most similar items
        logger.info("\nTop 5 Most Similar Items:")
        logger.info("----------------------------")
        for result in results[:5]:
            score = result['similarity_score']
            item_id = result['item_id']
            logger.info(f"{score:.3f} - {item_id}", extra={'emoji': False})
        
        # Print statistics
        logger.info("\nStatistics:")
        logger.info("--------------")
        logger.info(f"Average similarity: {statistics['avg_score']:.3f}")
        logger.info(f"Median similarity: {statistics['median_score']:.3f}")
        logger.info(f"Max similarity: {statistics['max_score']:.3f}")
        logger.info(f"Min similarity: {statistics['min_score']:.3f}")
        logger.info("")
    
def analyze_item_parallel(args: tuple) -> Dict:
    """
    Parallel processing of embeddings
    
    Args:
        args: Tuple containing analysis arguments
        
    Returns:
        Dict with analysis results
    """
    try:
        # Create a new Ollama client for each process
        client = OllamaManager(args.api_url).get_client()
        
        # Build vulnerability embedding prompt directly
        vuln_data = args.vulnerability
        
        rich_prompt = build_vulnerability_embedding_prompt(vuln_data)

        # Get vulnerability embedding
        vuln_response = client.embeddings(
            model=args.embedding_model,
            prompt=rich_prompt
        )

        if not vuln_response or 'embedding' not in vuln_response:
            return None

        # Get embedding from data
        if args.is_function:
            item_embedding = args.data['embedding']
        elif isinstance(args.data.get('embedding'), dict):
            item_embedding = args.data['embedding'].get('embedding')
        elif isinstance(args.data.get('embedding'), list) and isinstance(args.data['embedding'][0], list):
            # Handle chunked files - use chunk with highest similarity
            chunk_vectors = args.data['embedding']
            similarities = []
            for chunk_vec in chunk_vectors:
                sim = calculate_similarity(vuln_response['embedding'], chunk_vec)
                similarities.append(sim)

            # Return highest similarity
            return (
                {
                    'item_id': args.item_id,
                    'similarity_score': max(similarities),
                    'is_function': args.is_function,
                }
                if similarities
                else None
            )
        else:
            item_embedding = args.data.get('embedding')

        if not item_embedding:
            return None

        # Calculate similarity
        similarity = calculate_similarity(
            vuln_response['embedding'],
            item_embedding
        )

        return {
            'item_id': args.item_id,
            'similarity_score': similarity,
            'is_function': args.is_function
        }

    except Exception as e:
        logger.exception(f"Error analyzing {args.item_id}: {str(e)}")
        return {
            'item_id': args.item_id,
            'error': str(e),
            'is_function': args.is_function
        }

def _get_structured_deep_instructions(vuln_name: str) -> str:
    """
    Instructions for structured JSON output (ChunkDeepAnalysis) aligned with prior Markdown intent.
    """
    schema_hint = json.dumps(ChunkDeepAnalysis.model_json_schema(), indent=2)
    return f"""
Respond with a single JSON object matching this JSON Schema (no markdown code fences around the JSON):
{schema_hint}

Populate "findings" with one object per distinct {vuln_name} vulnerability in this chunk. If none, return {{"findings": [], "notes": "No issues"}}.

{chunk_deep_prompt_output_constraint_block()}

For each finding:
- title: short label (e.g. "Vulnerability found")
- vulnerable_code: exact snippet related ONLY to {vuln_name}
- explanation: why it is vulnerable to {vuln_name} only
- severity: one of Critical, High, Medium, Low
- impact: potential impact for this {vuln_name} case
- entry_point: route, API endpoint, function or method
- execution_path_diagram: ASCII-only diagram text (no markdown headers inside this string)
- http_methods: list of methods if applicable (e.g. GET, POST)
- manipulable_parameters: parameter or header names
- exploitation_steps: short bullet strings for the attack path
- example_payloads: example strings if applicable
- exploitation_conditions: dependencies or preconditions
- remediation: remediation guidance
- secure_code_example: optional secure code sample as plain text

Rules:
- DO NOT mention any vulnerability type other than {vuln_name}.
- If no {vuln_name} issues exist, return an empty findings array.

Valid vs invalid typing examples:
- valid: "exploitation_conditions": "Attacker can reach POST /transfer while authenticated."
- invalid: "exploitation_conditions": ["User is authenticated", "Endpoint is reachable"]
"""
