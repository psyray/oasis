from datetime import datetime
import logging
from pathlib import Path
import numpy as np
from typing import List, Dict
from weasyprint.logger import LOGGER as weasyprint_logger

# Import configuration
from .config import KEYWORD_LISTS, MODEL_EMOJIS, VULNERABILITY_MAPPING

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

    @staticmethod  
    def has_emoji_prefix(text: str) -> bool:  
        emoji_ranges = [  
            (0x1F300, 0x1F9FF),  # Misc Symbols & Pictographs  
            (0x2600, 0x26FF),    # Misc Symbols  
            (0x2700, 0x27BF),    # Dingbats  
            (0x1F600, 0x1F64F),  # Emoticons  
            (0x1F680, 0x1F6FF),  # Transport & Map Symbols  
        ]  
        if not text:  
            return False  
        first_char = text.strip()[0]  
        code = ord(first_char)  
        return any(start <= code <= end for start, end in emoji_ranges)  

    def determine_icon(self, record) -> str:  
        if not isinstance(record.msg, str) or self.has_emoji_prefix(
            record.msg.strip()
        ):  
            return ''
        msg_lower = record.msg.lower()
        if record.levelno == logging.DEBUG:  
            return '🪲  '
        if record.levelno == logging.INFO:  
            # Prioritize model emojis  
            for model_name, emoji in MODEL_EMOJIS.items():  
                if model_name.lower() in msg_lower:  
                    return ''  
            if any(word in msg_lower for word in KEYWORD_LISTS['INSTALL_WORDS']):  
                return '📥 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['ANALYSIS_WORDS']):  
                return '🔎 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['GENERATION_WORDS']):  
                return '⚙️  '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['REPORT_WORDS']):  
                return '📄 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['MODEL_WORDS']):  
                return '🤖 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['CACHE_WORDS']):  
                return '💾 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['SAVE_WORDS']):  
                return '💾 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['LOAD_WORDS']):  
                return '📂 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['STOPPED_WORDS']):  
                return '🛑 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['DELETE_WORDS']):  
                return '🗑️ '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['SUCCESS_WORDS']):  
                return '✅ '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['STATISTICS_WORDS']):  
                return '📊 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['TOP_WORDS']):  
                return '🏆 '  
            elif any(word in msg_lower for word in KEYWORD_LISTS['VULNERABILITY_WORDS']):  
                return '🚨 '  
            return ''  # Default for INFO level  
        if record.levelno == logging.WARNING:  
            return '⚠️  '
        if record.levelno == logging.ERROR:  
            return '💥 ' if any(word in record.msg.lower() for word in KEYWORD_LISTS['FAIL_WORDS']) else '❌ '
        return '🚨 ' if record.levelno == logging.CRITICAL else ''  

    def format(self, record):  
        if hasattr(record, 'emoji') and not record.emoji:  
            return record.msg  
        if not hasattr(record, 'formatted_message'):  
            icon = self.determine_icon(record)  
            if record.msg.startswith('\n'):  
                record.formatted_message = record.msg.replace('\n', f'\n{icon}', 1)  
            else:  
                record.formatted_message = f"{icon}{record.msg}"  
        return record.formatted_message

def setup_logging(debug=False, silent=False, error_log_file=None):
    """
    Setup all loggers with proper configuration

    Args:
        debug: Enable debug logging
        silent: Disable all output
        error_log_file: Path to error log file (used only in silent mode)
    """
    # Set root logger level
    root_logger = logging.getLogger()

    # Avoid adding duplicate handlers if they already exist.
    if root_logger.handlers:
        return

    if debug:
        root_logger.setLevel(logging.DEBUG)
    else:
        root_logger.setLevel(logging.INFO)

    # Configure handlers based on silent mode
    if not silent:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(EmojiFormatter())
        logger.addHandler(console_handler)

    # Add file handler for errors in silent mode
    if silent and error_log_file:
        file_handler = logging.FileHandler(error_log_file)
        file_handler.setLevel(logging.ERROR)  # Only log errors and above
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    logger.propagate = False  # Prevent duplicate logging

    # Set OASIS logger level based on mode
    if silent and not error_log_file:
        logger.setLevel(logging.CRITICAL + 1)  # Above all levels (complete silence)
    elif silent:
        logger.setLevel(logging.ERROR)         # Only errors and above if logging to file
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

def extract_clean_path(input_path: str | Path) -> Path:
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

def parse_input(input_path: str | Path) -> List[Path]:
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
            logger.exception(f"Error reading paths file: {str(e)}")
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

def sanitize_name(name: str) -> str:
    """
    Sanitize name for directory creation

    Args:
        name: Original name (e.g. 'whiterabbitneo_latest')
    Returns:
        Sanitized name (e.g. 'whiterabbitneo_latest')
    """
    # Get the last part after the last slash (if any)
    base_name = name.split('/')[-1]
    # Replace any remaining special characters
    return base_name.replace(':', '_')

def display_logo():
    """
    Display the OASIS logo
    """
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

def open_file(file_path: str) -> str:
    """
    Open a file and return its content

    Args:
        file_path: Path to the file
    Returns:
        Content of the file
    """
    # Try different encodings
    encodings = ['utf-8', 'latin-1', 'cp1252', 'iso-8859-1']
    content = None
    
    errors = []
    for encoding in encodings:
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                content = f.read()
            break
        except UnicodeDecodeError:
            errors.append(f"Failed to decode with {encoding}")
            continue
        except Exception as e:
            error_msg = f"Error reading {file_path} with {encoding}: {e.__class__.__name__}: {str(e)}"
            logger.exception(error_msg)
            errors.append(error_msg)
            continue
    
    if content is None:
        error_details = "; ".join(errors)
        logger.error(f"Failed to read {file_path}: Tried encodings {', '.join(encodings)}. Errors: {error_details}")
        return None
    
    return content

def get_vulnerability_mapping() -> Dict[str, Dict[str, any]]:
    """
    Return the vulnerability mapping

    Returns:
        Vulnerability mapping
    """
    return VULNERABILITY_MAPPING

def generate_timestamp(for_file: bool = False) -> str:
    """
    Generate a timestamp in the format YYYY-MM-DD HH:MM:SS
    """
    if for_file:
        return datetime.now().strftime("%Y%m%d_%H%M%S")
    else:
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
