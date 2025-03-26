from pathlib import Path
import yaml
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class TechnologyContextManager:
    def __init__(self, contexts_dir: str = "oasis/contexts"):
        self.contexts_dir = Path(contexts_dir)
        self.loaded_context = None
        self.tech_stack = None
        
        # Load language configurations
        self.language_extensions = {}
        self.framework_indicators = {}
        self._load_language_configurations()

    def _load_language_configurations(self):
        """Load all language configurations from yaml files"""
        for lang_dir in self.contexts_dir.glob('*'):
            if lang_dir.is_dir():
                language = lang_dir.name
                config_file = lang_dir / 'config.yaml'

                if config_file.exists():
                    if config := self._load_yaml(config_file):
                        # Load language extensions
                        self.language_extensions[language] = config.get('extensions', [])
                        # Load framework indicators
                        self.framework_indicators[language] = config.get('frameworks', {})

    def load_context(self, language: str, framework: Optional[str] = None) -> Dict:
        """Load technology context from yaml files"""
        base_context = self._load_yaml(self.contexts_dir / f"{language}/base.yaml")
        
        framework_context = {}
        if framework:
            framework_path = self.contexts_dir / f"{language}/{framework}.yaml"
            framework_context = self._load_yaml(framework_path)
            
        self.loaded_context = {**base_context, **framework_context}
        self.tech_stack = {"language": language, "framework": framework}
        
        return self.loaded_context

    def detect_technology_stack(self) -> Tuple[str, Optional[str]]:
        """Detect technology stack from codebase or get from args"""
        if hasattr(self.args, 'language') and self.args.language:
            return self._get_manual_technology_context()
        
        detected = self._auto_detect_stack()
        if detected[0]:
            logger.info(
                f"Detected technology stack: {detected[0]}{f' with {detected[1]}' if detected[1] else ''}"
            )
        return detected

    def _get_manual_technology_context(self) -> Tuple[Optional[str], Optional[str]]:
        """Get technology context from manual configuration"""
        language = self.args.language.lower()
        framework = self.args.framework.lower() if hasattr(self.args, 'framework') and self.args.framework else None

        # Validate language context
        if not self._validate_language_context(language):
            return None, None

        # Validate framework context if specified
        if framework and not self._validate_framework_context(language, framework):
            framework = None

        return language, framework

    def _validate_language_context(self, language: str) -> bool:
        """Validate that language context exists"""
        context_path = self.contexts_dir / language
        if not context_path.exists():
            logger.warning(f"No context found for language '{language}'. Running without technical context.")
            return False
        return True

    def _validate_framework_context(self, language: str, framework: str) -> bool:
        """Validate that framework context exists"""
        framework_path = self.contexts_dir / language / f"{framework}.yaml"
        if not framework_path.exists():
            logger.warning(f"No context found for framework '{framework}'. Using only language context.")
            return False
        return True

    def _auto_detect_stack(self) -> Tuple[Optional[str], Optional[str]]:
        """Automatically detect the technology stack"""
        input_path = Path(self.args.input_path)
        
        # Detect primary language
        detected_language = self._detect_primary_language(input_path)
        if not detected_language:
            return None, None

        # Update extensions in args to match detected language
        if hasattr(self.args, 'extensions'):
            self.args.extensions = self.get_language_extensions(detected_language)

        # Detect framework for the detected language
        framework = self._detect_framework(input_path, detected_language)

        return detected_language, framework

    def _detect_primary_language(self, input_path: Path) -> Optional[str]:
        """Detect primary programming language based on file extensions"""
        extension_count = self._count_file_extensions(input_path)
        if not extension_count:
            return None

        primary_ext = max(extension_count.items(), key=lambda x: x[1])[0]

        return next(
            (
                lang
                for lang, exts in self.language_extensions.items()
                if primary_ext in exts
            ),
            None,
        )

    def _count_file_extensions(self, input_path: Path) -> Dict[str, int]:
        """Count occurrences of each file extension"""
        extension_count = {}
        for file in input_path.rglob('*'):
            if file.is_file():
                if ext := file.suffix.lower().lstrip('.'):
                    extension_count[ext] = extension_count.get(ext, 0) + 1
        return extension_count

    def _detect_framework(self, input_path: Path, language: str) -> Optional[str]:
        """Detect framework based on framework indicators"""
        if language not in self.framework_indicators:
            return None

        return next(
            (
                framework
                for framework, indicators in self.framework_indicators[
                    language
                ].items()
                if self._check_framework_indicators(input_path, indicators)
            ),
            None,
        )

    def _check_framework_indicators(self, input_path: Path, indicators: list) -> bool:
        """Check if any framework indicators are present"""
        return any((input_path / indicator).exists() for indicator in indicators)

    def get_language_extensions(self, language: Optional[str] = None) -> list:
        """Get file extensions for a specific language or all supported extensions"""
        if language and language.lower() in self.language_extensions:
            return self.language_extensions[language.lower()]
        return [ext for exts in self.language_extensions.values() for ext in exts]

    def get_ignore_patterns(self) -> list:
        """Get patterns for files/directories to ignore"""
        return self.loaded_context.get("ignore_patterns", [])
        
    def get_security_context(self) -> str:
        """Get security-related context for LLM prompts"""
        return self.loaded_context.get("security_context", "")
        
    def _load_yaml(self, path: Path) -> Dict:
        """Load and parse YAML file"""
        try:
            if path.exists():
                with open(path) as f:
                    return yaml.safe_load(f)
            logger.warning(f"Context file not found: {path}")
            return {}
        except Exception as e:
            logger.error(f"Error loading context file {path}: {e}")
            return {}
