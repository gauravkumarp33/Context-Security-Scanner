from typing import Tuple

def classify_environment(file_path: str) -> Tuple[str, str, str]:
    path_lower = file_path.lower()
    if "test" in path_lower or "fixture" in path_lower or "spec" in path_lower:
        return "test", "high", "Path contains test or fixture keywords"
    elif "prod" in path_lower or "deploy" in path_lower or "dockerfile" in path_lower:
        return "production", "high", "Path indicates production or deployment config"
    elif "dev" in path_lower or "local" in path_lower:
        return "development", "medium", "Path indicates local or dev configuration"
    else:
        return "unknown", "low", "Could not reliably classify environment"