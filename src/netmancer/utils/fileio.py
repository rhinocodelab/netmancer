# src/netmancer/utils/fileio.py

import json
from pathlib import Path

def safe_write_json(data, path, overwrite=False):
    """Safely write JSON data to a file"""
    path = Path(path).resolve()
    
    if path.exists() and not overwrite:
        raise FileExistsError(f"File {path} already exists")
    
    if not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    
    with path.open('w') as f:
        json.dump(data, f, indent=4)
    
    return path