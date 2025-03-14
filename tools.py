import logging
from pathlib import Path
import numpy as np
from typing import List
from datetime import datetime
from weasyprint.logger import LOGGER as weasyprint_logger

# Initialize logger with module name
logger = logging.getLogger('oasis')

# Suppress weasyprint warnings
logging.getLogger('weasyprint').setLevel(logging.ERROR)

class EmojiFormatter(logging.Formatter):
    """
    Custom formatter that adds contextual emojis to log messages.
    
    Handles:
    - Automatic emoji detection
    - Level-based icons
    - Context-aware icons
    - Newline preservation
    """
    # Constants
    KEYWORD_LISTS = {
        'INSTALL_WORDS': ['installing', 'download', 'pulling', 'fetching'],
        'ANALYSIS_WORDS': ['analyzing', 'analysis', 'scanning', 'checking', 'inspecting', 'examining'],
        'GENERATION_WORDS': ['generating', 'creating', 'building', 'processing'],
        'MODEL_WORDS': ['model', 'ai', 'llm'],
        'CACHE_WORDS': ['cache', 'stored', 'saving'],
        'SAVE_WORDS': ['saved', 'written', 'exported'],
        'LOAD_WORDS': ['loading', 'reading', 'importing', 'loaded'],
        'FAIL_WORDS': ['failed', 'error', 'crash', 'exception']
    }    
    # Dictionary of model identifiers and their emojis (attribut de classe)
    MODEL_EMOJIS = {
        # General models
        "deepseek": "🧠 ",
        "llama": "🦙 ",
        "gemma": "💎 ",
        "mistral": "💨 ",
        "mixtral": "🌪️ ", 
        "qwen": "🐧 ",
        "phi": "φ ",
        "yi": "🌐 ",
        
        # Code models
        "codestral": "🌠 ",
        "starcoder": "⭐ ",
        
        # Interaction models
        "instruct": "💬 ",
        "chat": "💬 ",
        
        # Cybersecurity models
        "cybersecurity": "🛡️  ",
        "whiterabbit": "🐇 ",
        "sast": "🛡️  ",
        
        # Other models
        "research": "🔬 ",
        "openhermes": "🌟 ",
        "solar": "☀️ ",
        "neural-chat": "🧠💬 ",
        "nous": "👥 "
    }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Constants
        self.KEYWORD_LISTS = {
            'INSTALL_WORDS': ['installing', 'download', 'pulling', 'fetching'],
            'ANALYSIS_WORDS': ['analyzing', 'analysis', 'scanning', 'checking', 'inspecting', 'examining'],
            'GENERATION_WORDS': ['generating', 'creating', 'building', 'processing'],
            'MODEL_WORDS': ['model', 'ai', 'llm'],
            'CACHE_WORDS': ['cache', 'stored', 'saving'],
            'SAVE_WORDS': ['saved', 'written', 'exported'],
            'LOAD_WORDS': ['loading', 'reading', 'importing', 'loaded'],
            'FAIL_WORDS': ['failed', 'error', 'crash', 'exception']
        }
    def format(self, record):
        if not hasattr(record, 'formatted_message'):
            # Helper function to detect if string starts with emoji
            def has_emoji_prefix(text: str) -> bool:
                # Common emoji ranges in Unicode
                emoji_ranges = [
                    (0x1F300, 0x1F9FF),  # Miscellaneous Symbols and Pictographs
                    (0x2600, 0x26FF),    # Miscellaneous Symbols
                    (0x2700, 0x27BF),    # Dingbats
                    (0x1F600, 0x1F64F),  # Emoticons
                    (0x1F680, 0x1F6FF),  # Transport and Map Symbols
                ]
                
                if not text:
                    return False
                    
                # Get the first character code
                first_char = text.strip()[0]
                code = ord(first_char)
                
                # Check if it falls in emoji ranges
                return any(start <= code <= end for start, end in emoji_ranges)

            # Start with default icon (nothing)
            icon = ''
            
            # Check if record.msg is a string before using string methods
            if isinstance(record.msg, str):
                # Get the appropriate icon based on level and content if no emoji exists
                if not has_emoji_prefix(record.msg.strip()):
                    if record.levelno == logging.DEBUG:
                        icon = '🪲  '  # Debug: beetle
                    elif record.levelno == logging.INFO:
                        msg_lower = record.msg.lower()
                        
                        # Check for model names first (higher priority)
                        model_found = False
                        for model_name, _ in self.MODEL_EMOJIS.items():
                            if model_name.lower() in msg_lower:
                                model_found = True
                                break
                        
                        # If no model was found, check for other keywords
                        if not model_found:
                            if any(word in msg_lower for word in self.KEYWORD_LISTS['INSTALL_WORDS']):
                                icon = '📥 '  # Download/Install
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['ANALYSIS_WORDS']):
                                icon = '🔎 '  # Analysis
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['GENERATION_WORDS']):
                                icon = '⚙️  '  # Generation/Processing
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['MODEL_WORDS']):
                                icon = '🤖 '  # AI/Model
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['CACHE_WORDS']):
                                icon = '💾 '  # Cache/Save
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['SAVE_WORDS']):
                                icon = '💾 '  # Save
                            elif any(word in msg_lower for word in self.KEYWORD_LISTS['LOAD_WORDS']):
                                icon = '📂 '  # Loading
                            else:
                                icon = ''  # Default info
                    elif record.levelno == logging.WARNING:
                        icon = '⚠️  '  # Warning
                    elif record.levelno == logging.ERROR:
                        if any(word in record.msg.lower() for word in self.KEYWORD_LISTS['FAIL_WORDS']):
                            icon = '💥 '  # Crash
                        else:
                            icon = '❌ '  # Standard error
                    elif record.levelno == logging.CRITICAL:
                        icon = '🚨 '  # Critical/Fatal

                    # Handle messages starting with newline
                    if record.msg.startswith('\n'):
                        record.formatted_message = record.msg.replace('\n', '\n' + icon, 1)
                    else:
                        record.formatted_message = f"{icon}{record.msg}"
                else:
                    record.formatted_message = record.msg
            else:
                # Handle non-string messages (like lists, dicts, etc.)
                record.formatted_message = f"🪲  {str(record.msg)}"

        return record.formatted_message

def setup_logging(debug=False, silent=False):
    """
    Setup all loggers with proper configuration
    Args:
        debug: Enable debug logging
        silent: Disable all output
    """
    # Set root logger level
    root_logger = logging.getLogger()
    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)

    # Configure handlers based on silent mode
    if not silent:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(EmojiFormatter())
        logger.addHandler(console_handler)
    
    logger.propagate = False  # Prevent duplicate logging
    
    # Set OASIS logger level based on mode
    if silent:
        logger.setLevel(logging.CRITICAL + 1)  # Above all levels
    elif debug:
        logger.setLevel(logging.DEBUG)         # Show all messages
    else:
        logger.setLevel(logging.INFO)          # Show info, warning, error

    # Configure other loggers
    fonttools_logger = logging.getLogger('fontTools')
    fonttools_logger.setLevel(logging.ERROR)
    
    weasyprint_logger.setLevel(logging.ERROR)

    # Disable other verbose loggers
    logging.getLogger('PIL').setLevel(logging.WARNING)
    logging.getLogger('markdown').setLevel(logging.WARNING)

def chunk_content(content: str, max_length: int = 2048) -> List[str]:
    """
    Split content into chunks of maximum length while preserving line integrity
    Args:
        content: Text content to split
        max_length: Maximum length of each chunk (reduced to 2048 to be safe)
    Returns:
        List of content chunks
    """
    if len(content) <= max_length:
        return [content]

    chunks = []
    lines = content.splitlines()
    current_chunk = []
    current_length = 0

    for line in lines:
        line_length = len(line) + 1  # +1 for newline
        if current_length + line_length > max_length:
            if current_chunk:
                chunks.append('\n'.join(current_chunk))
            current_chunk = [line]
            current_length = line_length
        else:
            current_chunk.append(line)
            current_length += line_length

    if current_chunk:
        chunks.append('\n'.join(current_chunk))

    logger.debug(f"Split content of {len(content)} chars into {len(chunks)} chunks")

    return chunks

def extract_clean_path(input_path):
    """
    Extract a clean path from input that might contain additional arguments
    
    Args:
        input_path: Path string or Path object potentially containing additional arguments
        
    Returns:
        Clean path in the same format as input (Path object or string)
    """
    # Determine input type to preserve it for output
    is_path_object = isinstance(input_path, Path)
    
    # Convert to string for processing
    input_path_str = str(input_path)
    
    # Extract the actual path before any arguments
    path_parts = input_path_str.split()
    actual_path = path_parts[0] if path_parts else input_path_str
    
    # Handle quoted paths (remove quotes if present)
    if actual_path.startswith('"') and actual_path.endswith('"'):
        actual_path = actual_path[1:-1]
    elif actual_path.startswith("'") and actual_path.endswith("'"):
        actual_path = actual_path[1:-1]
    
    logger.debug(f"Extracted clean path: {actual_path} from input: {input_path_str}")
    
    # Return in the same format as input
    return Path(actual_path) if is_path_object else actual_path

def parse_input(input_path: str) -> List[Path]:
    """
    Parse input path and return list of files to analyze
    Args:
        input_path: Path to file, directory, or file containing paths
    Returns:
        List of Path objects to analyze
    """
    # Get clean path without arguments, and ensure it's a Path object
    clean_path_str = extract_clean_path(input_path)
    input_path = Path(clean_path_str)  # Convert to Path object for processing
    
    files_to_analyze = []

    # Case 1: Input is a file containing paths
    if input_path.suffix == '.txt':
        try:
            with open(input_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
                for path in paths:
                    p = Path(path)
                    if p.is_file():
                        files_to_analyze.append(p)
                    elif p.is_dir():
                        files_to_analyze.extend(
                            f for f in p.rglob('*') 
                            if f.is_file()
                        )
        except Exception as e:
            logger.error(f"Error reading paths file: {str(e)}")
            return []

    # Case 2: Input is a single file
    elif input_path.is_file():
        files_to_analyze.append(input_path)

    # Case 3: Input is a directory
    elif input_path.is_dir():
        files_to_analyze.extend(
            f for f in input_path.rglob('*') 
            if f.is_file()
        )

    else:
        logger.error(f"Invalid input path: {input_path}")
        return []

    return files_to_analyze

def get_output_directory(input_path: str, base_reports_dir: Path) -> Path:
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
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir_name = f"{input_name}_{timestamp}"
    
    return base_reports_dir / output_dir_name

def sanitize_model_name(model: str) -> str:
    """
    Sanitize model name for directory creation
    Args:
        model: Original model name (e.g. 'rfc/whiterabbitneo:latest')
    Returns:
        Sanitized name (e.g. 'whiterabbitneo_latest')
    """
    # Get the last part after the last slash (if any)
    base_name = model.split('/')[-1]
    # Replace any remaining special characters
    return base_name.replace(':', '_')

def display_logo():
    logo = """
     .d88b.    db    .d8888.  _\\\\|//_ .d8888. 
    .8P  Y8.  d88b   88'  YP    \\\\//  88'  YP 
    88    88 d8'`8b  `8bo.       ||     `8bo.   
    88    88 88ooo88   `Y8b.     ||       `Y8b. 
    `8b  d8' 88~~~88 db   8D    /||\\   db   8D 
     `Y88P'  YP  YP  `8888Y' __/_||_\\_ `8888Y' 

╔════════════════════════════════════════════════╗
║ Ollama Automated Security Intelligence Scanner ║
╚════════════════════════════════════════════════╝
"""
    logger.info(logo)

def calculate_similarity(embedding1: List[float], embedding2: List[float]) -> float:
    """
    Calculate cosine similarity between two embeddings
    Args:
        embedding1: First embedding vector
        embedding2: Second embedding vector
    Returns:
        Cosine similarity score (0-1)
    """
    # Convert to numpy arrays for efficient computation
    vec1 = np.array(embedding1)
    vec2 = np.array(embedding2)
    
    # Calculate cosine similarity
    dot_product = np.dot(vec1, vec2)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
        
    return float(dot_product / (norm1 * norm2)) 