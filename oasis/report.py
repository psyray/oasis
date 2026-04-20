import base64
import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup
import markdown
from markdown.extensions import Extension
from markdown.preprocessors import Preprocessor
from jinja2 import Environment, FileSystemLoader

# Import from configuration
from .config import REPORT, LANGUAGES

# Import from other modules
from .export import artifact_filename
from .export.vulnerability import write_vulnerability_artifacts
from .export.markdown_outputs import write_rendered_markdown_formats
from .export.writers import write_markdown_lines, write_utf8_text
from .schemas.analysis import (
    ChunkDeepAnalysis,
    FileReportEntry,
    VulnerabilityReportDocument,
    build_dashboard_stats,
    chunk_analysis_to_markdown,
)
from .tools import extract_clean_path, logger, sanitize_name, generate_timestamp

# Package metadata (process constant; avoid lazy imports in hot paths)
from . import __version__ as oasis_version
from .helpers.langgraph_console import langgraph_emit_report_delivery
from .helpers.progress import (
    SCAN_PROGRESS_EXTENDED_KEYS,
    SCAN_PROGRESS_NON_PARTIAL_STATUSES,
    SCAN_PROGRESS_STATUS_EXPLICIT,
)
from .helpers.executive_summary_similarity import (
    EXEC_SUMMARY_EMBEDDING_TIER_ORDER,
    executive_summary_similarity_tier_id,
)
from .helpers.executive_summary_links import dashboard_reports_href, preferred_detail_relative_path_and_format
from .helpers.scan_progress_md import (
    append_adaptive_subphases_markdown,
    append_pipeline_phases_markdown,
    notifier_vulnerability_counts,
    scan_progress_status_meta,
    scan_progress_tested_and_current,
    scan_progress_vulnerability_counts,
)


def progress_timestamp_iso() -> str:
    """UTC ISO-8601 timestamp used as incremental scan ``updated_at``.

    **Contract**

    - **Shape**: UTC with millisecond precision, ``Z`` suffix (never ``+00:00``). Built from
      :meth:`datetime.datetime.isoformat` + ``.replace("+00:00", "Z")``. Milliseconds reduce
      collisions when multiple updates occur within the same wall-clock second.
    - **Ordering**: for this shape, lexicographic string order matches chronological order.
      The dashboard (`DashboardApp.applyProgressPayload` in ``api.js``) compares incoming
      and previous ``updated_at`` strings without ``Date.parse`` to reject stale snapshots.
    - **Where written**: :func:`publish_incremental_summary` injects a default when callers
      omit ``updated_at``; final / milestone updates often pass ``updated_at=progress_timestamp_iso()``.

    If the format ever changes, update the client comparison (or switch both sides to a
    numeric epoch) so staleness detection stays correct.
    """
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def executive_summary_progress_sidecar_path(json_path: Path) -> Path:
    """Sibling path for incremental scan progress JSON (does not replace canonical reports).

    Example: ``.../json/_executive_summary.json`` → ``.../json/_executive_summary.progress.json``.
    """
    return json_path.with_name(f"{json_path.stem}.progress{json_path.suffix}")


def is_executive_summary_progress_sidecar(path: Path) -> bool:
    """
    True for incremental progress sidecar files — not canonical vulnerability report JSON.

    Dashboard indexing must skip these so they are not opened as HTML/JSON reports.
    """
    return path.suffix.lower() == ".json" and path.stem.endswith(".progress")


class Report:
    """
    Class for generating security analysis reports in multiple formats

    Args:
        input_path: Path to the input file or directory
        output_format: List of output formats to generate
    """
    
    def __init__(self, input_path: str | Path, output_format: List[str], models: List[str] = None, 
                 current_model: str = None, language: str = 'en'):
        """
        Initialize the report generator
        
        Args:
            input_path: Path to the input file or directory
            output_format: List of output formats to generate
            models: List of models to generate reports for
            current_model: Current model being used
            language: Language code for reports (default: en)
        """
        if models is None:
            models = []

        # Initialize the report generator
        self.input_path = input_path
        self.output_format = output_format
        self.report_dirs = {}
        self.models = models
        self.current_model = current_model
        self.original_language = language
        normalized_language = str(language or "en").strip().lower()
        self.language_code = normalized_language.split("-", 1)[0].split("_", 1)[0] or "en"
        if self.language_code not in LANGUAGES:
            logger.warning(
                "Unsupported language code '%s' (normalized from %r); falling back to default language 'en'. Available languages: %s",
                self.language_code,
                self.original_language,
                ", ".join(sorted(LANGUAGES.keys())),
            )
            self.language_code = "en"
        self.language = LANGUAGES[self.language_code]
        self.progress_notifier = None
        self._notifying_progress = False
        self._last_summary_results: Dict[str, List[Dict]] = {}
        self._last_summary_model_name: str = ""
        self._last_progress_payload: Dict[str, Any] = {}
        self._executive_summary_sidecar_write_failed = False
        self.executive_summary_scan_model: str = ""
        self.executive_summary_embedding_model: str = ""


        # Configure the Jinja2 environment
        template_dir = Path(__file__).parent / 'templates'
        self.template_env = Environment(loader=FileSystemLoader(searchpath=str(template_dir)))

    def set_progress_notifier(self, notifier) -> None:
        """Register an optional callback receiving real-time scan progress payloads."""
        self.progress_notifier = notifier

    def set_executive_summary_models(
        self,
        *,
        scan_model: Optional[str] = None,
        embedding_model: Optional[str] = None,
    ) -> None:
        """Persist model metadata used by executive-summary rendering."""
        if scan_model is not None:
            self.executive_summary_scan_model = str(scan_model or "")
        if embedding_model is not None:
            self.executive_summary_embedding_model = str(embedding_model or "")

    def mark_progress_aborted(self) -> None:
        """Publish an aborted progress snapshot after a user interruption.

        This method intentionally reuses ``generate_executive_summary`` so the
        persisted summary and notifier payload stay aligned.
        """
        if not self._last_progress_payload:
            return

        progress = dict(self._last_progress_payload)
        progress["status"] = "aborted"
        # Fresh timestamp so dashboard readers / Socket.IO dedupe see a new snapshot (status-only changes).
        progress["updated_at"] = progress_timestamp_iso()

        self.generate_executive_summary(
            self._last_summary_results,
            self._last_summary_model_name or self.current_model or "",
            progress=progress,
        )

    def ensure_directory(self, directory: Path) -> None:
        """
        Ensure directory exists

        Args:
            directory: Path to the directory
        """
        directory.mkdir(parents=True, exist_ok=True)
    
    def create_report_directories(self, input_path: str | Path, sub_dir: str = None, models: List[str] = None) -> Dict[str, Path]:
        """
        Create format-specific directories for reports
        
        Args:
            input_path: Path to the input file or directory
            sub_dir: Optional subdirectory name
            
        Returns:
            Dictionary of format-specific directory paths
        """
        if isinstance(input_path, str):
            input_path = Path(input_path)

        self.output_base_dir = input_path.resolve().parent / REPORT['OUTPUT_DIR']
        self.output_dir = self.get_output_directory(input_path, self.output_base_dir)
        self.ensure_directory(self.output_base_dir)

        base_dir = self.output_dir
        if sub_dir:
            base_dir = base_dir / sub_dir
            self.ensure_directory(base_dir)

        models_dir = []
        if models:
            for model in models:
                model_dir = sanitize_name(model)
                models_dir.append(model_dir)
                self.report_dirs[model_dir] = {}

        # Create format-specific directories with only the requested formats
        for fmt in self.output_format:
            if fmt in REPORT['OUTPUT_FORMATS'] and models_dir:
                for model_dir in models_dir:
                    self.report_dirs[model_dir][fmt] = base_dir / model_dir / fmt
                    self.ensure_directory(self.report_dirs[model_dir][fmt])
                    
                    # Create language.txt file in the report directory
                    lang_file = self.report_dirs[model_dir][fmt].parent / 'language.txt'
                    with open(lang_file, 'w', encoding='utf-8') as f:
                        f.write(self.language_code)

        return self.report_dirs
    
    def create_header(self, title: str, model_name: Optional[str] = None) -> List[str]:
        """
        Create a standard report header
        
        Args:
            title: Report title
            model_name: Optional model name to include
            
        Returns:
            List of header lines
        """
        header = [
            f"# {title}",
            f"\nDate: {generate_timestamp()}"
        ]
        
        if model_name:
            header.append(f"\nModel: {model_name}")
            
        return header
    
    def _results_to_file_entries(self, results: List[Dict]) -> List[FileReportEntry]:
        analysis_notes_max_len = 2000
        truncation_suffix = " [truncated]"
        entries: List[FileReportEntry] = []
        for result in results:
            chunk_models: List[ChunkDeepAnalysis] = []
            for raw in result.get("structured_chunks") or []:
                try:
                    if isinstance(raw, dict):
                        raw_copy = dict(raw)
                        notes = raw_copy.get("notes")
                        truncated = bool(raw_copy.get("truncated", False))
                        if isinstance(notes, str) and len(notes) > analysis_notes_max_len:
                            raw_copy["notes"] = (
                                notes[: analysis_notes_max_len - len(truncation_suffix)]
                                + truncation_suffix
                            )
                            truncated = True
                        raw_copy["truncated"] = truncated
                        chunk_models.append(ChunkDeepAnalysis.model_validate(raw_copy))
                    else:
                        chunk_models.append(ChunkDeepAnalysis.model_validate(raw))
                except Exception:
                    raw_str = str(raw)
                    truncated = False
                    if len(raw_str) > analysis_notes_max_len:
                        raw_str = (
                            raw_str[: analysis_notes_max_len - len(truncation_suffix)]
                            + truncation_suffix
                        )
                        truncated = True
                    chunk_models.append(
                        ChunkDeepAnalysis(findings=[], notes=raw_str, truncated=truncated)
                    )
            if not chunk_models and result.get("analysis"):
                analysis_str = str(result["analysis"])
                truncated = False
                if len(analysis_str) > analysis_notes_max_len:
                    analysis_str = (
                        analysis_str[: analysis_notes_max_len - len(truncation_suffix)]
                        + truncation_suffix
                    )
                    truncated = True
                chunk_models.append(
                    ChunkDeepAnalysis(findings=[], notes=analysis_str, truncated=truncated)
                )
            entries.append(
                FileReportEntry(
                    file_path=result.get("file_path", "Unknown file"),
                    similarity_score=float(result.get("similarity_score", 0.0)),
                    chunk_analyses=chunk_models,
                    error=result.get("error"),
                )
            )
        return entries

    def _build_vulnerability_document(
        self, vulnerability: Dict, results: List[Dict], model_name: str
    ) -> VulnerabilityReportDocument:
        vuln_name = vulnerability["name"]
        file_entries = self._results_to_file_entries(results)
        stats = self._compute_document_stats(file_entries)
        return VulnerabilityReportDocument(
            title=f"{vuln_name} Security Analysis",
            generated_at=generate_timestamp(),
            model_name=model_name,
            language=self.language_code,
            vulnerability_name=vuln_name,
            vulnerability=dict(vulnerability),
            files=file_entries,
            stats=stats,
        )

    @staticmethod
    def _compute_document_stats(file_entries: List[FileReportEntry]):
        """Single source of truth for dashboard statistics aggregation."""
        return build_dashboard_stats(file_entries)

    def _render_vulnerability_inner_html(self, doc: VulnerabilityReportDocument) -> str:
        template = self.template_env.get_template("reports/vulnerability_from_json.html.j2")
        return template.render(document=doc.model_dump(mode="json"))

    def _render_vulnerability_markdown_export(self, doc: VulnerabilityReportDocument) -> str:
        template = self.template_env.get_template("reports/vulnerability_export.md.j2")
        return template.render(document=doc.model_dump(mode="json"))

    def render_report_html_from_json_payload(self, payload: Dict) -> str:
        """
        Render report HTML directly from canonical JSON payload.
        """
        report_type = payload.get("report_type")
        if report_type != "vulnerability":
            raise ValueError(f"Unsupported canonical report type: {report_type}")

        doc = VulnerabilityReportDocument.model_validate(payload)
        # Keep JSON payload and template rendering aligned on one stats helper.
        doc.stats = self._compute_document_stats(doc.files)
        inner_html = self._render_vulnerability_inner_html(doc)
        return self.render_template(inner_html)

    def generate_vulnerability_report(
        self, vulnerability: Dict, results: List[Dict], model_name: str
    ) -> Dict[str, Path]:
        """
        Generate vulnerability report: canonical JSON plus Jinja-derived HTML/PDF and optional MD export.
        """
        vuln_name = vulnerability["name"]
        safe_name = vuln_name.lower().replace(" ", "_")
        output_files = self.filter_output_files(safe_name)
        doc = self._build_vulnerability_document(vulnerability, results, model_name)

        logger.debug("--------------------------------")
        logger.debug(f"Generating Vulnerability report for {', '.join(self.output_format)}, please wait...")

        inner_html = self._render_vulnerability_inner_html(doc)
        rendered_html = self.render_template(inner_html)
        md_body = ""
        if "md" in output_files:
            md_body = self._render_vulnerability_markdown_export(doc)

        written = write_vulnerability_artifacts(
            output_files,
            doc,
            rendered_html=rendered_html,
            md_body=md_body,
            logger=logger,
            safe_name_for_logs=safe_name,
            tool_version=oasis_version,
        )
        if missing := [k for k, p in written.items() if p is None]:
            logger.warning(
                "Some vulnerability report artifacts failed for %s (formats: %s)",
                safe_name,
                ", ".join(missing),
            )
        return {k: p for k, p in written.items() if p is not None}
    
    def _generate_and_save_report(self, output_files, report_content, report_type: str = None):
        """
        Write report content and convert to all configured formats

        Args:
            output_files: Dictionary of output file paths
            report_content: List of report content lines
            report_type: Type of report (Vulnerability, Audit, Executive Summary)
        """
        logger.debug("--------------------------------")
        logger.debug(f"Generating {report_type} report for {', '.join(self.output_format)}, please wait...")

        # Write markdown
        write_markdown_lines(output_files["md"], report_content, logger)

        # Convert to PDF and HTML
        self.convert_to_all_formats(output_files["md"])

    def report_generated(self, report_type: str = None, report_structure: bool = False):
        """
        Log that a report has been generated

        Args:
            report_type: Type of report (Vulnerability, Audit, Executive Summary)
            report_structure: Whether to display the report structure
        """
        langgraph_emit_report_delivery(logger, report_type, str(self.output_dir))
        
        # Show report structure
        if report_structure:
            self.display_report_structure()


    def generate_audit_report(self, analyzer_results: Dict[str, Dict], 
                            embedding_manager) -> Dict[str, Path]:
        """
        Generate audit report from analyzer results
        
        Args:
            analyzer_results: Results from EmbeddingAnalyzer
            embedding_manager: EmbeddingManager instance
            
        Returns:
            Dictionary of report file paths
        """
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files("audit_report")
        summary_metrics = self._audit_metrics_summary(analyzer_results)
        report = self._build_audit_report_header(embedding_manager)
        self._extend_audit_metrics_summary(report, summary_metrics)
        self._extend_audit_vulnerability_statistics(report, analyzer_results)
        self._extend_audit_analysis_results(report, analyzer_results)

        # Generate and save report
        self._generate_and_save_report(output_files, report, report_type='Audit')

        return output_files

    @staticmethod
    def _build_audit_report_header(embedding_manager) -> List[str]:
        embeddings_info = embedding_manager.get_embeddings_info()
        return [
            "# Embeddings Distribution Analysis Report",
            f"\nDate: {generate_timestamp()}",
            f"\nEmbedding Model: {embedding_manager.embedding_model}",
            f"\nTotal Files Analyzed: {embeddings_info['total_files']}",
            REPORT["EXPLAIN_ANALYSIS"],
            '<div class="page-break"></div>',
        ]

    @staticmethod
    def _extend_audit_metrics_summary(report: List[str], summary_metrics: Dict[str, Any]) -> None:
        if not summary_metrics:
            return

        def _as_int(metric_name: str, fallback: int = 0) -> int:
            return int(summary_metrics.get(metric_name, fallback) or 0)

        def _as_float(metric_name: str) -> float | None:
            raw_value = summary_metrics.get(metric_name)
            if raw_value is None:
                return None
            try:
                numeric = float(raw_value)
            except (TypeError, ValueError):
                return None
            return numeric if math.isfinite(numeric) else None

        def _append_score_row(rows: List[str], label: str, metric_name: str) -> None:
            score_value = _as_float(metric_name)
            if score_value is None:
                return
            rows.append(f"| {label} | {score_value:.3f} |")

        total_items = int(summary_metrics.get("total_items", summary_metrics.get("count", 0)) or 0)
        scored_items = int(summary_metrics.get("scored_items", summary_metrics.get("count", 0)) or 0)
        has_scores = bool(summary_metrics.get("has_scores", _as_int("count") > 0))
        if not has_scores:
            report.extend(
                [
                    "\n## Audit Metrics Summary\n",
                    "> No audit metrics are available (no scored items).",
                    f"> Total items: {total_items}",
                    f"> Scored items: {scored_items}",
                ]
            )
            return
        summary_rows = [
            "\n## Audit Metrics Summary\n",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Count | {_as_int('count')} |",
            f"| Total items | {total_items} |",
            f"| Scored items | {scored_items} |",
        ]
        _append_score_row(summary_rows, "Average similarity", "avg_score")
        _append_score_row(summary_rows, "Median similarity", "median_score")
        _append_score_row(summary_rows, "Maximum similarity", "max_score")
        _append_score_row(summary_rows, "Minimum similarity", "min_score")
        summary_rows.extend(
            [
                f"| High matches (>= 0.8) | {_as_int('high')} |",
                f"| Medium matches (>= 0.6 and < 0.8) | {_as_int('medium')} |",
                f"| Low matches (>= 0.4 and < 0.6) | {_as_int('low')} |",
            ]
        )
        report.extend(summary_rows)

    @staticmethod
    def _extend_audit_vulnerability_statistics(
        report: List[str], analyzer_results: Dict[str, Dict]
    ) -> None:
        vuln_stats = analyzer_results.get("vulnerability_statistics", [])
        if not vuln_stats:
            return
        report.extend(
            [
                "\n## Vulnerability Statistics\n",
                "| Vulnerability Type | Total | High | Medium | Low |",
                "|-------------------|-------|------|--------|-----|",
            ]
        )
        for stat in vuln_stats:
            if stat.get("is_total", False):
                report.append(
                    f"| **{stat['name']}** | **{stat['total']}** | **{stat['high']}** | **{stat['medium']}** | **{stat['low']}** |"
                )
                continue
            report.append(
                f"| {stat['name']} | {stat['total']} | {stat['high']} | {stat['medium']} | {stat['low']} |"
            )

    def _extend_audit_analysis_results(self, report: List[str], analyzer_results: Dict[str, Dict]) -> None:
        report.append("\n## Analysis Results\n")
        section_index = 0
        for vuln_name, data in analyzer_results.items():
            if vuln_name == "vulnerability_statistics":
                continue
            if section_index > 0:
                report.append("\n<div class=\"page-break\"></div>\n")
            self._extend_audit_vulnerability_result_section(report, vuln_name, data)
            section_index += 1

    @staticmethod
    def _extend_audit_vulnerability_result_section(
        report: List[str], vuln_name: str, data: Dict[str, Any]
    ) -> None:
        report.extend(
            [
                f"### {vuln_name}",
                "#### Threshold Analysis",
                "| Threshold | Matching Items | Percentage |",
                "|-----------|----------------|------------|",
            ]
        )
        for analysis in data["threshold_analysis"]:
            threshold = analysis["threshold"]
            matching_items = analysis["matching_items"]
            percentage = analysis["percentage"]
            report.append(f"| {threshold:.1f} | {matching_items} | {percentage:.1f}% |")

        report.extend(
            [
                "\n#### Top Matches",
                "| Score | Item |",
                "|-------|------|",
            ]
        )
        for result in data["results"][:10]:
            score = result["similarity_score"]
            item_id = result["item_id"]
            report.append(f"| {score:.3f} | {item_id} |")

        stats = data["statistics"]
        report.extend(
            [
                "\n#### Statistics",
                f"- **Average similarity**: {stats['avg_score']:.3f}",
                f"- **Median similarity**: {stats['median_score']:.3f}",
                f"- **Maximum similarity**: {stats['max_score']:.3f}",
                f"- **Minimum similarity**: {stats['min_score']:.3f}",
            ]
        )

    @staticmethod
    def _audit_metrics_summary(analyzer_results: Dict[str, Dict]) -> Dict[str, Any]:
        """
        Build one comparable metrics summary from audit analyzer results.
        """
        def _as_float_score(value: Any) -> float | None:
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                return None
            return numeric if math.isfinite(numeric) else None

        total_row = next(
            (
                row
                for row in analyzer_results.get("vulnerability_statistics", [])
                or []
                if row.get("is_total")
            ),
            None,
        )
        if total_row is None:
            return {}

        all_scores: List[float] = []
        for vuln_name, data in analyzer_results.items():
            if vuln_name == "vulnerability_statistics":
                continue
            if not isinstance(data, dict):
                continue
            for result in data.get("results", []) or []:
                score = _as_float_score(result.get("similarity_score"))
                if score is not None:
                    all_scores.append(score)

        if not all_scores:
            total_items = int(total_row.get("total", 0) or 0)
            return {
                "count": 0,
                "has_scores": False,
                "total_items": total_items,
                "scored_items": 0,
                "avg_score": 0.0,
                "median_score": 0.0,
                "max_score": 0.0,
                "min_score": 0.0,
                "high": int(total_row.get("high", 0) or 0),
                "medium": int(total_row.get("medium", 0) or 0),
                "low": int(total_row.get("low", 0) or 0),
            }

        scores_sorted = sorted(all_scores)
        mid = len(scores_sorted) // 2
        if len(scores_sorted) % 2 == 0:
            median = (scores_sorted[mid - 1] + scores_sorted[mid]) / 2
        else:
            median = scores_sorted[mid]

        total_items = int(total_row.get("total", len(all_scores)) or 0)
        scored_items = len(all_scores)
        return {
            "count": scored_items,
            "has_scores": True,
            "total_items": total_items,
            "scored_items": scored_items,
            "avg_score": float(sum(all_scores) / len(all_scores)),
            "median_score": float(median),
            "max_score": float(max(all_scores)),
            "min_score": float(min(all_scores)),
            "high": int(total_row.get("high", 0) or 0),
            "medium": int(total_row.get("medium", 0) or 0),
            "low": int(total_row.get("low", 0) or 0),
        }

    def _executive_summary_similarity_groups(
        self, all_results: Dict[str, List[Dict]]
    ) -> Dict[str, List[Dict[str, Any]]]:
        groups: Dict[str, List[Dict[str, Any]]] = {
            tier_id: [] for tier_id, _ in EXEC_SUMMARY_EMBEDDING_TIER_ORDER
        }
        for vuln_type, results in all_results.items():
            for result in results:
                score = result["similarity_score"]
                tier = executive_summary_similarity_tier_id(score)
                if tier not in groups:
                    continue
                groups[tier].append(
                    {
                        "vuln_type": vuln_type,
                        "file_path": result["file_path"],
                        "score": score,
                    }
                )
        return groups

    @staticmethod
    def _extend_executive_summary_vulnerability_table(
        report: List[str], all_results: Dict[str, List[Dict]]
    ) -> None:
        vulnerability_count = {vt: len(rs) for vt, rs in all_results.items()}
        report.extend(
            [
                "\n## Vulnerability Summary",
                "| Vulnerability Type | Files Analyzed |",
                "|-------------------|----------------|",
            ]
        )
        report.extend(f"| {vuln_type} | {count} |" for vuln_type, count in vulnerability_count.items())

    def _extend_executive_summary_similarity_sections(
        self, report: List[str], similarity_groups: Dict[str, List[Dict[str, Any]]]
    ) -> None:
        for tier_id, tier_title in EXEC_SUMMARY_EMBEDDING_TIER_ORDER:
            findings = similarity_groups.get(tier_id) or []
            if not findings:
                continue
            report.extend(
                [
                    f"\n## {tier_title} — {len(findings)} matches",
                    "| Vulnerability Type | File | Similarity | Report Link |",
                    "|-------------------|------|------------|--------------|",
                ]
            )
            for finding in sorted(findings, key=lambda x: x["score"], reverse=True):
                stem = finding["vuln_type"].lower().replace(" ", "_")
                rel_path, _fmt = preferred_detail_relative_path_and_format(self, stem)
                href = dashboard_reports_href(rel_path)
                report.append(
                    f"| {finding['vuln_type']} | `{finding['file_path']}` | {finding['score']:.2f} | "
                    f"[Details]({href}) |"
                )

    def _get_executive_summary_model_names(self, model_name: object) -> tuple[str, str, str]:
        """Return normalized (deep, small, embedding) model names."""
        deep_model_name = str(model_name).strip()
        scan_model_name = str(getattr(self, "executive_summary_scan_model", "") or "").strip()
        embedding_model_name = str(getattr(self, "executive_summary_embedding_model", "") or "").strip()
        return deep_model_name, scan_model_name, embedding_model_name
    
    def generate_executive_summary(
        self,
        all_results: Dict[str, List[Dict]],
        model_name: str,
        progress: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Path]:
        """
        Generate executive summary report
        
        Args:
            all_results: Dictionary of all vulnerability results
            model_name: Name of model used
            
        Returns:
            Dictionary of report file paths
        """
        output_files = self.filter_output_files("_executive_summary")
        self._last_summary_results = dict(all_results or {})
        self._last_summary_model_name = str(model_name or "")

        report = self.create_header("Executive Summary", model_name)
        report.extend([
            "\n## Overview",
            f"\nAnalyzed {len(all_results)} vulnerability types across the codebase.",
            REPORT['EXPLAIN_EXECUTIVE_SUMMARY'],
        ])
        deep_model_name, scan_model_name, embedding_model_name = self._get_executive_summary_model_names(
            model_name
        )
        report.extend(
            [
                "\n## Models Used",
                f"- Deep model: {deep_model_name or 'N/A'}",
                f"- Small model: {scan_model_name or 'N/A'}",
                f"- Embedding model: {embedding_model_name or 'N/A'}",
            ]
        )

        if progress:
            self._append_scan_progress_section(progress, report)

        self._extend_executive_summary_vulnerability_table(report, all_results)
        similarity_groups = self._executive_summary_similarity_groups(all_results)
        self._extend_executive_summary_similarity_sections(report, similarity_groups)

        report.extend([
            "\n---",
            f"Report generated on: {generate_timestamp()}",
            f"Deep model: {deep_model_name}",
            f"Small model: {scan_model_name or 'N/A'}",
            f"Embedding model: {embedding_model_name or 'N/A'}",
        ])

        self._generate_and_save_report(output_files, report, report_type='Executive Summary')

        json_path = output_files.get("json")
        if progress and json_path:
            try:
                progress_path = executive_summary_progress_sidecar_path(Path(json_path))
                # Compatibility: keep legacy `model` as primary deep-model field for existing
                # consumers; newer readers can use explicit `deep_model`/`small_model`/`embedding_model`.
                doc = {
                    "report_type": "executive_summary",
                    "model": model_name,
                    "deep_model": deep_model_name,
                    "small_model": scan_model_name,
                    "embedding_model": embedding_model_name,
                    "progress": dict(self._last_progress_payload),
                    "generated_at": progress_timestamp_iso(),
                    "oasis_version": oasis_version,
                }
                write_utf8_text(
                    progress_path,
                    json.dumps(doc, indent=2, ensure_ascii=False),
                )
            except Exception:
                if not self._executive_summary_sidecar_write_failed:
                    self._executive_summary_sidecar_write_failed = True
                    logger.warning(
                        "Failed to write executive summary progress sidecar JSON "
                        "(subsequent failures will be logged at debug level only)",
                        exc_info=True,
                    )
                else:
                    logger.debug(
                        "Failed to write executive summary progress sidecar JSON",
                        exc_info=True,
                    )

        notifier = getattr(self, "progress_notifier", None)
        if progress and callable(notifier):
            self._notify_progress_update(progress=progress, model_name=model_name, notifier=notifier)

        return output_files

    def _append_scan_progress_section(self, progress, report):
        completed, total = scan_progress_vulnerability_counts(progress)
        is_partial, status_key, status_label = scan_progress_status_meta(progress)
        tested_vulnerabilities, current_vulnerability = scan_progress_tested_and_current(progress)

        report.extend(
            [
                "\n## Scan Progress",
                "| Status | Completed vulnerabilities |",
                "|--------|----------------------------|",
                f"| {status_label} | {completed}/{total} |",
            ]
        )
        if current_vulnerability:
            report.append(f"- Current vulnerability: {current_vulnerability}")
        if tested_vulnerabilities:
            report.append("- Tested vulnerabilities: " + ", ".join(tested_vulnerabilities))

        append_pipeline_phases_markdown(report, progress.get("phases"))
        append_adaptive_subphases_markdown(report, progress.get("adaptive_subphases"))

        payload: Dict[str, Any] = {
            "completed_vulnerabilities": completed,
            "total_vulnerabilities": total,
            "is_partial": is_partial,
            "status": status_key,
            "current_vulnerability": current_vulnerability,
            "tested_vulnerabilities": tested_vulnerabilities,
        }
        for key in SCAN_PROGRESS_EXTENDED_KEYS:
            if key in progress:
                payload[key] = progress[key]
        self._last_progress_payload = payload

    def _build_progress_notifier_payload(
        self, progress: Dict[str, Any], model_name: str
    ) -> Dict[str, Any]:
        """Normalize scan progress fields for realtime notifier callbacks."""
        fallback_total = (
            (self._last_progress_payload or {}).get("total_vulnerabilities")
            if hasattr(self, "_last_progress_payload")
            else None
        )
        completed, total = notifier_vulnerability_counts(
            progress, fallback_total=fallback_total
        )

        out: Dict[str, Any] = {
            "completed_vulnerabilities": completed,
            "total_vulnerabilities": total,
            "is_partial": bool(progress.get("is_partial", False)),
            "status": str(
                progress.get("status")
                or ("in_progress" if progress.get("is_partial") else "complete")
            ),
            "model": model_name,
            "current_vulnerability": str(progress.get("current_vulnerability") or ""),
            "tested_vulnerabilities": [
                str(item).strip()
                for item in (progress.get("tested_vulnerabilities") or [])
                if str(item).strip()
            ],
        }
        for key in SCAN_PROGRESS_EXTENDED_KEYS:
            if key in progress:
                out[key] = progress[key]
        return out

    def _notify_progress_update(self, progress: Dict[str, Any], model_name: str, notifier) -> None:
        """Call progress notifier with a re-entrancy guard."""
        if getattr(self, "_notifying_progress", False):
            logger.debug("Skipping re-entrant progress notifier call")
            return
        try:
            self._notifying_progress = True
            notifier(self._build_progress_notifier_payload(progress, model_name))
        except Exception:
            logger.debug("Progress notifier failed", exc_info=True)
        finally:
            self._notifying_progress = False
    
    def convert_to_all_formats(self, markdown_file: Path) -> Dict[str, Path]:
        """
        Convert markdown file to PDF and HTML
        
        Args:
            markdown_file: Path to markdown file
            
        Returns:
            Dictionary of output files
        """
        # Set output file paths and filter by output format in one step
        output_files = self.filter_output_files(markdown_file.stem)

        try:
            html_content = self.read_and_convert_markdown(markdown_file)
            rendered_html = self.render_template(html_content)
            return write_rendered_markdown_formats(
                output_files,
                rendered_html,
                logger=logger,
                context_label=markdown_file.name,
            )
        except Exception as e:
            logger.exception(f"Error converting {markdown_file.name} to other formats: {e.__class__.__name__}: {str(e)}")
            if logger.isEnabledFor(logging.DEBUG):
                logger.debug("Full error:", exc_info=True)

            return {
                "md": markdown_file,
                "pdf": None,
                "html": None,
            }

    def read_and_convert_markdown(self, markdown_file: Path) -> str:
        """
        Read markdown file and convert to HTML
        
        Args:
            markdown_file: Path to markdown file
            
        Returns:
            HTML content
        """
        # Read markdown content
        markdown_content = markdown_file.read_text(encoding="utf-8")

        # Parse HTML with Beautiful Soup and fix any issues
        soup = BeautifulSoup(markdown.markdown(markdown_content, extensions=['tables', 'fenced_code', 'codehilite']), 'html.parser')
        fixed_html = str(soup)

        # Convert markdown to HTML with page break extension, using the fixed HTML
        return markdown.markdown(
            fixed_html,
            extensions=['tables', 'fenced_code', 'codehilite', PageBreakExtension()]
        )
    
    def render_template(self, content: str) -> str:
        """
        Render HTML content using Jinja2 template
        
        Args:
            content: HTML content to render
            
        Returns:
            Rendered HTML
        """
        try:
            # Get the absolute path of the logo
            images_dir = Path(__file__).parent / 'images'
            logo_path = images_dir / 'oasis-logo.jpg'
            
            # Encode the logo in base64
            encoded_string = base64.b64encode(logo_path.read_bytes()).decode("utf-8")
            
            # Create a data URL for the image
            logo_data_url = f"data:image/jpeg;base64,{encoded_string}"
            
            template = self.template_env.get_template('report_template.html')
            return template.render(content=content, logo_path=logo_data_url, background_color=REPORT['BACKGROUND_COLOR'])
        except Exception as e:
            logger.exception(f"Error rendering template: {str(e)}")
            # Fallback to basic HTML if template fails
            return f"<html><body>{content}</body></html>"
    
    def normalize_heading_levels(self, content: str, base_level: int = 5) -> str:
        """
        Adjust the markdown heading levels to start at a specified level
        
        Args:
            content: Markdown content to normalize
            base_level: Base level for the highest heading (default: 5)
            
        Returns:
            Content with normalized heading levels
        """
        lines = content.split('\n')
        result = []
        
        # Find the lowest heading level (less #)
        min_level = float('inf')
        for line in lines:
            if line.strip().startswith('#'):
                # Count the # at the beginning
                level = 0
                for char in line:
                    if char == '#':
                        level += 1
                    else:
                        break
                min_level = min(min_level, level)
        
        # If no heading found, return original content
        if min_level == float('inf'):
            return content
        
        # Normalize the headings
        for line in lines:
            if line.strip().startswith('#'):
                # Count the # at the beginning
                level = 0
                for char in line:
                    if char == '#':
                        level += 1
                    else:
                        break
                
                # Calculate the new level
                new_level = base_level + (level - min_level)
                # Rebuild the line with the correct number of #
                new_line = '#' * new_level + line[level:]
                result.append(new_line)
            else:
                result.append(line)
        
        return '\n'.join(result)
    
    def display_report_structure(self) -> None:
        """
        Display the structure of generated report files        
        """
        logger.info("\nGenerated files structure:")
        
        models = self.models or ['embed_model']
        for model in models:
            model_name = sanitize_name(model)
            if model_name == 'embed_model':
                model_dir = self.output_dir
                model_dir_name = self.output_dir_name
            else:
                model_dir = self.output_dir / model_name
                model_dir_name = model_name
            if not model_dir.is_dir():
                continue

            logger.info(f"\n{model_dir_name}/", extra={'emoji': False})
            for fmt_dir in model_dir.glob('*'):
                if not fmt_dir.is_dir():
                    continue
                    
                logger.info(f"  └── {fmt_dir.name}/", extra={'emoji': False})
                for report in fmt_dir.glob('*.*'):
                    logger.info(f"       └── {report.name}", extra={'emoji': False})
        
        logger.info("")

    def filter_output_files(self, safe_name: str) -> Dict[str, Path]:
        """
        Filter output files based on the output_format list

        Args:
            safe_name: Safe name for the report
            
        Returns:
            Dictionary of output files
        """
        model_name = sanitize_name(self.current_model)
        return {
            fmt: self.report_dirs[model_name][fmt] / artifact_filename(safe_name, fmt)
            for fmt in self.output_format
            if fmt in self.report_dirs[model_name]
        }

    def get_output_directory(self, input_path: str | Path, base_reports_dir: Path) -> Path:
        """
        Generate a unique output directory name based on input path and timestamp
        
        Args:
            input_path: Input path (string or Path) that may contain arguments
            base_reports_dir: Base directory for reports
            
        Returns:
            Unique output directory path
        """
        # Make sure we have a clean path
        clean_path = extract_clean_path(input_path)
            
        # Get basename for naming the output directory
        input_name = clean_path.name if clean_path.is_file() else clean_path.stem
        
        # Add timestamp for uniqueness
        timestamp = generate_timestamp(for_file=True)
        self.output_dir_name = f"{input_name}_{timestamp}"
        
        return base_reports_dir / self.output_dir_name


def publish_incremental_summary(
    report: Report,
    llm_model: str,
    all_results: Dict[str, List[Dict]],
    *,
    completed_vulnerabilities: int,
    total_vulnerabilities: int,
    current_vulnerability: str | None,
    tested_vulnerabilities: List[str],
    **progress_extras: Any,
) -> None:
    """Centralize executive-summary updates for LangGraph and legacy incremental progress.

    ``total_vulnerabilities`` is the denominator for ``completed_vulnerabilities`` /
    ``is_partial`` for the **current** reporting step. LangGraph callers typically pass
    ``vulnerability_types_total`` and pipeline ``phases`` via ``progress_extras`` (see
    ``SCAN_PROGRESS_EXTENDED_KEYS``).

    Keyword arguments beyond the explicit parameters are merged only when the key is in
    ``SCAN_PROGRESS_EXTENDED_KEYS``, matching ``Report._append_scan_progress_section`` so
    arbitrary caller data cannot be persisted into executive-summary artifacts.

    If ``progress_extras`` includes a validated ``status`` string, it overrides the default
    ``in_progress`` / ``complete`` pair derived from counts; ``is_partial`` is then derived
    from that status (non-partial only for success-style terminals in
    ``SCAN_PROGRESS_NON_PARTIAL_STATUSES``). Invalid status values are ignored.
    """
    status_override = str(progress_extras.get("status") or "").strip()
    override_lower = status_override.lower()
    if status_override and override_lower in SCAN_PROGRESS_STATUS_EXPLICIT:
        effective_status = override_lower
        is_partial = effective_status not in SCAN_PROGRESS_NON_PARTIAL_STATUSES
    else:
        derived_status_key = (
            "in_progress" if completed_vulnerabilities < total_vulnerabilities else "complete"
        )
        effective_status = derived_status_key
        derived_partial = completed_vulnerabilities < total_vulnerabilities
        is_partial = derived_partial

    extras_allowed = {
        key: val
        for key, val in progress_extras.items()
        if key in SCAN_PROGRESS_EXTENDED_KEYS and val is not None
    }
    extras_allowed.pop("status", None)

    payload: Dict[str, Any] = {
        "completed_vulnerabilities": completed_vulnerabilities,
        "total_vulnerabilities": total_vulnerabilities,
        "is_partial": is_partial,
        "status": effective_status,
        "current_vulnerability": current_vulnerability,
        "tested_vulnerabilities": tested_vulnerabilities,
    }
    if "updated_at" not in extras_allowed:
        payload["updated_at"] = progress_timestamp_iso()
    payload |= extras_allowed
    report.generate_executive_summary(all_results, llm_model, progress=payload)


def build_adaptive_deep_phase_markdown(
    file_display_name: str,
    *,
    total_chunks: int,
    suspicious_count: int,
    medium_analyzed: int,
    medium_validation_errors: int,
    deep_analyzed: int,
    vulnerable_items: List[Tuple[Any, ChunkDeepAnalysis]],
    unparsed_deep_chunks: List[Dict[str, Any]],
    suspect_deep_count: int,
) -> str:
    """
    Legacy helper: adaptive-style deep-phase Markdown (unused by current GRAPH pipeline).

    ``vulnerable_items`` is a list of (chunk_idx, chunk_model) pairs for chunks with findings.
    """
    suspicious_pct = (suspicious_count / total_chunks * 100) if total_chunks else 0.0

    summary = f"""## Adaptive Security Analysis for {file_display_name}

### Analysis Summary:
- **Total code chunks analyzed**: {total_chunks}
- **Suspicious chunks identified**: {suspicious_count} ({suspicious_pct:.1f}%)
- **Context-sensitive chunks analyzed**: {medium_analyzed}
- **Medium-analysis validation errors**: {medium_validation_errors}
- **High-risk chunks deeply analyzed**: {deep_analyzed}
- **Vulnerable chunks found**: {len(vulnerable_items)}
- **Unparseable deep-analysis chunks**: {len(unparsed_deep_chunks)}
- **Potential vulnerabilities (parse-failure suspects)**: {suspect_deep_count}
"""
    report_parts: List[str] = [summary]

    if vulnerable_items:
        report_parts.append("\n## Identified Vulnerabilities\n")

        for i, (chunk_idx, chunk_model) in enumerate(vulnerable_items):
            analysis_body = chunk_analysis_to_markdown(chunk_model, chunk_idx)
            section_header = f"### Vulnerability #{i+1} - Chunk {chunk_idx+1}\n"
            report_parts.extend((section_header + analysis_body, "\n<div class=\"page-break\"></div>\n"))
    else:
        report_parts.append("\n## No vulnerabilities were found in the deep analysis phase.\n")

    if unparsed_deep_chunks:
        report_parts.append("\n## Unparseable deep analyses\n")
        for chunk in unparsed_deep_chunks:
            chunk_idx = chunk.get("chunk_idx", "unknown")
            raw = str(chunk.get("analysis", "") or "")
            note = raw if len(raw) <= 300 else f"{raw[:300]}... [truncated]"
            escaped_note = note.replace("```", "``\\`")
            report_parts.append(
                "- Chunk {idx}: structured deep analysis could not be parsed.\n\n"
                "  Notes (raw model output, truncated & escaped):\n\n"
                "  ```\n"
                "{note}\n"
                "  ```\n".format(
                    idx=chunk_idx,
                    note=escaped_note,
                )
            )

    return "\n".join(report_parts)


class PageBreakExtension(Extension):
    """
    Markdown extension to handle page breaks

    Args:
        md: Markdown instance
    """
    def extendMarkdown(self, md):
        md.preprocessors.register(PageBreakPreprocessor(md), 'page_break', 27)

class PageBreakPreprocessor(Preprocessor):
    """
    Preprocessor to convert marker to HTML

    Args:
        md: Markdown instance
    """
    def run(self, lines):
        new_lines = []
        for line in lines:
            if line.strip() == '<div class="page-break"></div>':
                new_lines.append('<div style="page-break-after: always"></div>')
            else:
                new_lines.append(line)
        return new_lines