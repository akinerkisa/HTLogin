import json
import os
from typing import Dict, Any

BANNER = """
    ██   ██ ████████ ██       ██████   ██████  ██ ███    ██
    ██   ██    ██    ██      ██    ██ ██       ██ ████   ██
    ███████    ██    ██      ██    ██ ██   ███ ██ ██ ██  ██
    ██   ██    ██    ██      ██    ██ ██    ██ ██ ██  ██ ██
    ██   ██    ██    ███████  ██████   ██████  ██ ██   ████   v1.1.1 github.com/akinerkisa/HTLogin
"""

_FALLBACK_CONFIG = {
    'timeout': 10,
    'max_retries': 2,
    'rate_limit_requests': 10,
    'rate_limit_threads': 10,
    'rate_limit_adaptive_delay': 1.0,
    'confidence_threshold_low': 20,
    'confidence_threshold_medium': 30,
    'confidence_threshold_high': 50,
    'show_progress': True,
    'http_method': 'POST',
    'language': 'en',
    'output_format': 'text',
    'verbose': False,
    'discovery_enabled': True,
    'discovery_verify_pages': True,
    'nosql_progressive_mode': True,
    'nosql_admin_patterns': ['admin.*', 'administrator.*', 'root.*', '.*admin.*', 'adm.*'],
    'safe_mode': False,
    'max_requests_per_target': 200,
}


def _load_default_config() -> Dict[str, Any]:
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    config_path = os.path.join(project_root, 'config.json')

    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
                return config
        except (json.JSONDecodeError, IOError) as e:
            return _FALLBACK_CONFIG.copy()
    else:
        return _FALLBACK_CONFIG.copy()


DEFAULT_CONFIG = _load_default_config()

