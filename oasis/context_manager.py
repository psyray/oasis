from pathlib import Path
import yaml
from typing import Dict, Optional, Tuple, List, Union
import logging
from dataclasses import dataclass
from functools import lru_cache
from collections import Counter

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityPattern:
    score: int
    description: str
    patterns: List[str]

class TechnologyContextManager:
    def __init__(self, args, contexts_dir: str = "oasis/contexts"):
        self.args = args
        self.contexts_dir = Path(contexts_dir)
        self.loaded_context = None
        self.tech_stack = None
    
        # Load language configurations
        self.language_extensions = {}
        self.framework_indicators = {}
        self.vulnerability_patterns = {}
        self.max_languages = 3  # Default value
        self._load_language_configurations()

    def _load_language_configurations(self):
        """Load all language configurations from yaml files"""
        for lang_dir in self.contexts_dir.glob('*'):
            if lang_dir.is_dir():
                language = lang_dir.name
                self.vulnerability_patterns[language] = {}
                
                # Load base language configuration
                config_file = lang_dir / 'config.yaml'
                if config := self._load_yaml(config_file):
                    self.language_extensions[language] = config.get('extensions', [])
                    self.framework_indicators[language] = config.get('frameworks', {})

                # Load base vulnerability patterns
                base_file = lang_dir / 'base.yaml'
                if base_patterns := self._load_yaml(base_file):
                    self.vulnerability_patterns[language]['base'] = base_patterns.get('vulnerability_patterns', {})

                # Load framework-specific patterns
                for framework_file in lang_dir.glob('*.yaml'):
                    if framework_file.stem not in ['config', 'base']:
                        if framework_patterns := self._load_yaml(framework_file):
                            self.vulnerability_patterns[language][framework_file.stem] = (
                                framework_patterns.get('vulnerability_patterns', {})
                            )

    @lru_cache(maxsize=32)
    def get_merged_vulnerability_patterns(self, language: str, framework: Optional[str] = None) -> Dict:
        """
        Get merged vulnerability patterns for a specific language and framework
        
        Args:
            language: Programming language
            framework: Optional framework name
            
        Returns:
            Dictionary of merged vulnerability patterns
        """
        if language not in self.vulnerability_patterns:
            return {}

        # Start with base patterns
        merged = self.vulnerability_patterns[language]['base'].copy()

        # Merge framework patterns if specified
        if framework and framework in self.vulnerability_patterns[language]:
            framework_patterns = self.vulnerability_patterns[language][framework]
            for vuln_type, framework_data in framework_patterns.items():
                if vuln_type not in merged:
                    merged[vuln_type] = framework_data
                else:
                    # Update score if framework has higher score
                    merged[vuln_type]['score'] = max(
                        merged[vuln_type].get('score', 0),
                        framework_data.get('score', 0)
                    )
                    # Extend patterns list while removing duplicates
                    base_patterns = set(merged[vuln_type].get('patterns', []))
                    framework_patterns = set(framework_data.get('patterns', []))
                    merged[vuln_type]['patterns'] = list(base_patterns | framework_patterns)

        return merged

    def load_context(self, language: str, framework: Optional[str] = None) -> Dict:
        """Load complete technology context including vulnerability patterns"""
        base_context = self._load_yaml(self.contexts_dir / f"{language}/base.yaml")
        
        # Get framework context if specified
        framework_context = {}
        if framework:
            framework_path = self.contexts_dir / f"{language}/{framework}.yaml"
            framework_context = self._load_yaml(framework_path)
            
        # Merge vulnerability patterns
        vulnerability_patterns = self.get_merged_vulnerability_patterns(language, framework)
        
        # Combine all contexts
        self.loaded_context = {
            **base_context,
            **framework_context,
            'vulnerability_patterns': vulnerability_patterns
        }
        
        self.tech_stack = {"language": language, "framework": framework}
        return self.loaded_context
    
    def detect_technology_stack(self) -> Tuple[str, Optional[str]]:
        """
        Detect technology stack from codebase or get from args
        
        Returns:
            Tuple of (language, framework)
            Returns (None, None) if autodetection is disabled and no manual config
        """
        # Check if autodetection should be disabled
        if self._should_disable_autodetection():
            # If language is manually specified, use manual context
            if hasattr(self.args, 'language') and self.args.language:
                return self._get_manual_technology_context()
            # Otherwise return None to indicate no technology context
            logger.info("Automatic technology detection is disabled and no language specified")
            return None, None
        
        # Proceed with autodetection
        detected = self._auto_detect_stack()
        if detected[0]:
            logger.info(
                f"Detected technology stack: {detected[0]}{f' with {detected[1]}' if detected[1] else ''}"
            )
        return detected

    def _should_disable_autodetection(self) -> bool:
        """
        Check if autodetection should be disabled based on arguments
        
        Returns:
            True if autodetection should be disabled, False otherwise
        """
        # Explicit no-autodetect flag
        if hasattr(self.args, 'no_autodetect') and self.args.no_autodetect:
            logger.debug("Autodetection disabled by --no-autodetect flag")
            return True
        
        # Check for manual configuration options that should disable autodetection
        has_manual_config = any([
            hasattr(self.args, 'language') and self.args.language,
            hasattr(self.args, 'framework') and self.args.framework,
            hasattr(self.args, 'extensions') and self.args.extensions
        ])
        
        if has_manual_config:
            logger.debug("Autodetection disabled due to manual configuration options")
            return True
        
        return False

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

    def _auto_detect_stack(self) -> List[Tuple[str, Optional[str]]]:
        """
        Automatically detect multiple technology stacks
        
        Returns:
            List of tuples (language, framework)
        """
        input_path = Path(self.args.input_path)
        
        # Get max languages from args or use default
        max_languages = getattr(self.args, 'max_languages', self.max_languages)
        
        # Detect languages by frequency
        detected_languages = self._detect_languages_by_frequency(input_path, max_languages)
        if not detected_languages:
            return []

        # Build technology stacks
        tech_stacks = []
        all_extensions = set()

        for lang, _ in detected_languages:
            # Get extensions for this language
            lang_extensions = self.get_language_extensions(lang)
            all_extensions.update(lang_extensions)
            
            # Detect framework for the language
            framework = self._detect_framework(input_path, lang)
            
            tech_stacks.append((lang, framework))

        # Update extensions in args to include all detected languages
        if hasattr(self.args, 'extensions'):
            self.args.extensions = list(all_extensions)

        return tech_stacks

    def _detect_languages_by_frequency(self, path: Path, max_languages: int) -> List[Tuple[str, int]]:
        """
        Detect languages by analyzing file extensions frequency
        
        Args:
            path: Path to analyze
            max_languages: Maximum number of languages to detect
            
        Returns:
            List of tuples (language, file_count) sorted by frequency
        """
        extension_counts = Counter()
        
        # Count files by extension
        for file in path.rglob('*'):
            if file.is_file():
                ext = file.suffix.lower().lstrip('.')
                if ext:
                    extension_counts[ext] += 1

        # Map extensions to languages
        language_counts = Counter()
        for ext, count in extension_counts.items():
            for lang, lang_extensions in self.language_extensions.items():
                if ext in lang_extensions:
                    language_counts[lang] += count
                    break

        # Get top N languages
        return language_counts.most_common(max_languages)

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
        
    def get_vulnerability_score(self, language: str, framework: Optional[str], vuln_type: str) -> int:
        """Get vulnerability score for a specific vulnerability type"""
        patterns = self.get_merged_vulnerability_patterns(language, framework)
        return patterns.get(vuln_type, {}).get('score', 5)  # Default score of 5

    def get_vulnerability_patterns(self, language: str, framework: Optional[str], vuln_type: str) -> List[str]:
        """Get patterns for a specific vulnerability type"""
        patterns = self.get_merged_vulnerability_patterns(language, framework)
        return patterns.get(vuln_type, {}).get('patterns', [])
        
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

    def display_tech_profile(self) -> str:
        """Generate a formatted display of the loaded technology profiles"""
        tech_stacks = self._auto_detect_stack()
        if not tech_stacks:
            return "No technology stack detected"

        output = ["=== Technology Profile ==="]
        
        # Display each detected language and its framework
        for i, (language, framework) in enumerate(tech_stacks, 1):
            output.extend([
                f"\nLanguage {i}: {language}",
                f"Framework: {framework or 'Not detected'}",
                "\nFile Extensions:",
                *[f"  - {ext}" for ext in self.language_extensions.get(language, [])]
            ])

            # Add vulnerability patterns for this language
            patterns = self.get_merged_vulnerability_patterns(language, framework)
            if patterns:
                output.extend([
                    "\nVulnerability Patterns:",
                    *[f"  - {vuln_type} (score: {data.get('score', 5)})" 
                      for vuln_type, data in patterns.items()]
                ])
            
            output.append("\n" + "="*30)  # Separator between languages

        return "\n".join(output)

    def detect_and_display_tech_stack(self, input_path: Path) -> Union[Tuple[str, Optional[str]], List[Tuple[str, Optional[str]]]]:
        """
        Detect technology stack and display loaded profile
        
        Args:
            input_path: Path to analyze
            
        Returns:
            If --tech-detect: List of tuples (language, framework)
            Otherwise: Tuple of (language, framework)
        """
        # Detect technology stack
        result = self._auto_detect_stack()
        
        if isinstance(result, list):
            # Multiple languages detected
            for language, framework in result:
                if language:
                    # Load context for each detected stack
                    self.load_context(language, framework)
            
            # Display complete profile
            logger.info("\n" + self.display_tech_profile())
            return result
        else:
            # Single language detection (backward compatibility)
            language, framework = result
            if language:
                # Load context for detected stack
                self.load_context(language, framework)
                
                # Display profile
                logger.info("\n" + self.display_tech_profile())
            else:
                logger.warning("No technology stack detected")

        return language, framework
