import os
from typing import List

EXCLUDED_DIRS = {'.git', '.venv', 'venv', 'node_modules', '__pycache__', 'dist', 'build'}

def analyze_repository(repo_path: str) -> List[str]:
    file_list = []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
        for file in files:
            rel_path = os.path.relpath(os.path.join(root, file), repo_path)
            file_list.append(rel_path)
    return file_list