#!/usr/bin/env python3
"""
Migration script to move all Python files to the oasis package
"""

import os
import shutil
from pathlib import Path

# Files to migrate
PYTHON_FILES = [
    'analyze.py',
    'config.py', 
    'embedding.py',
    'oasis.py',
    'ollama_manager.py',
    'report.py',
    'tools.py'
]

# Create oasis package directory if it doesn't exist
os.makedirs('oasis', exist_ok=True)

# Create __init__.py with main import
with open('oasis/__init__.py', 'w') as f:
    f.write('"""\nOASIS - Ollama Automated Security Intelligence Scanner\n"""\n\n')
    f.write('from .oasis import main\n\n')
    f.write('__version__ = "0.2.0"\n')

# Copy all Python files to the oasis directory
for file in PYTHON_FILES:
    if os.path.exists(file):
        print(f"Moving {file} to oasis/")
        shutil.copy2(file, os.path.join('oasis', file))

# Move templates folder
if os.path.exists('templates'):
    print("Moving templates/ to oasis/templates/")
    templates_dir = Path('oasis/templates')
    templates_dir.mkdir(exist_ok=True)
    
    # Copy template files
    for template_file in os.listdir('templates'):
        src = os.path.join('templates', template_file)
        dst = os.path.join('oasis/templates', template_file)
        shutil.copy2(src, dst)

print("Migration completed!")
print("\nNext steps:")
print("1. Update imports in all Python files in oasis/ to use relative imports")
print("2. Test the package with 'pip install -e .'")
print("3. After confirming everything works, you can delete the original Python files") 