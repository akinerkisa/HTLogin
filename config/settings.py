import json
import os
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field, asdict

from .constants import DEFAULT_CONFIG


@dataclass
class Config:
    timeout: int = 10
    max_retries: int = 2
    rate_limit_requests: int = 10
    rate_limit_threads: int = 10
    rate_limit_adaptive_delay: float = 1.0
    confidence_threshold_low: int = 20
    confidence_threshold_medium: int = 30
    confidence_threshold_high: int = 50
    show_progress: bool = True
    verbose: bool = False
    http_method: str = 'POST'
    language: str = 'en'
    output_format: str = 'text'
    output_file: Optional[str] = None
    log_file: Optional[str] = None
    proxy: Optional[str] = None
    credential_list_file: Optional[str] = None
    discovery_enabled: bool = True
    discovery_verify_pages: bool = True
    nosql_progressive_mode: bool = True
    nosql_admin_patterns: List[str] = field(default_factory=lambda: ['admin.*', 'administrator.*', 'root.*', '.*admin.*', 'adm.*'])
    test_account_username: Optional[str] = None
    test_account_password: Optional[str] = None
    use_selenium: bool = False
    selenium_headless: bool = True
    selenium_wait_time: int = 5
    user_agent: Optional[str] = None
    scan_mode: str = 'quick'
    verify_ssl: bool = True
    safe_mode: bool = False
    max_requests_per_target: int = 200

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        valid_fields = {}
        optional_str_fields = ['output_file', 'log_file', 'proxy', 'credential_list_file',
                              'test_account_username', 'test_account_password', 'user_agent']
        type_validators = {
            int: ['timeout', 'max_retries', 'rate_limit_requests', 'rate_limit_threads',
                  'confidence_threshold_low', 'confidence_threshold_medium', 'confidence_threshold_high',
                  'selenium_wait_time', 'max_requests_per_target'],
            float: ['rate_limit_adaptive_delay'],
            bool: ['show_progress', 'verbose', 'discovery_enabled', 'discovery_verify_pages',
                   'nosql_progressive_mode', 'use_selenium', 'selenium_headless', 'verify_ssl', 'safe_mode'],
            str: ['http_method', 'language', 'output_format', 'scan_mode'],
            list: ['nosql_admin_patterns'],
        }

        for key, value in data.items():
            if not hasattr(cls, key):
                continue

            if key in optional_str_fields:
                if value is None or isinstance(value, str):
                    valid_fields[key] = value
                else:
                    try:
                        valid_fields[key] = str(value) if value is not None else None
                    except (ValueError, TypeError):
                        from utils.logging import get_logger
                        logger = get_logger()
                        logger.warning(f"Skipping invalid config value for {key}: expected str or None, got {type(value).__name__}. Using default value.")
                continue

            expected_type = None
            for type_class, fields in type_validators.items():
                if key in fields:
                    expected_type = type_class
                    break

            if expected_type and not isinstance(value, expected_type):
                try:
                    if expected_type == int and isinstance(value, (str, float)):
                        value = int(float(value))
                    elif expected_type == float and isinstance(value, (str, int)):
                        value = float(value)
                    elif expected_type == bool and isinstance(value, (str, int)):
                        if isinstance(value, str):
                            value = value.lower() in ['true', '1', 'yes', 'on']
                        else:
                            value = bool(value)
                    elif expected_type == str and value is not None:
                        value = str(value)
                    else:
                        raise ValueError(f"Invalid type for {key}: expected {expected_type.__name__}, got {type(value).__name__}")
                except (ValueError, TypeError) as e:
                    from utils.logging import get_logger
                    logger = get_logger()
                    logger.warning(f"Skipping invalid config value for {key}: {e}. Using default value.")
                    continue

            valid_fields[key] = value

        return cls(**valid_fields)

    @classmethod
    def from_file(cls, filepath: str) -> 'Config':
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls.from_dict(data)
        except FileNotFoundError:
            raise FileNotFoundError(f"Config file not found: {filepath}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in config file {filepath}: {e}")
        except Exception as e:
            raise IOError(f"Error reading config file {filepath}: {e}")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save_to_file(self, filepath: str) -> None:
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

    def merge_cli_args(self, args: Dict[str, Any]) -> 'Config':
        config_dict = self.to_dict()
        for key, value in args.items():
            if value is not None and hasattr(self, key):
                config_dict[key] = value
        return self.from_dict(config_dict)


def get_config(cli_args: Optional[Dict[str, Any]] = None,
               config_file: Optional[str] = None) -> Config:
    config = Config.from_dict(DEFAULT_CONFIG)

    if config_file and os.path.exists(config_file):
        try:
            file_config = Config.from_file(config_file)
            config_dict = config.to_dict()
            file_dict = file_config.to_dict()
            for key, value in file_dict.items():
                if hasattr(Config, key):
                    config_dict[key] = value
            config = Config.from_dict(config_dict)
        except (FileNotFoundError, ValueError, IOError) as e:
            from utils.logging import get_logger
            logger = get_logger()
            logger.warning(f"Error loading config file {config_file}: {e}. Using defaults.")

    if cli_args:
        config = config.merge_cli_args(cli_args)

    return config

