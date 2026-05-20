import pytest
import configparser
from pathlib import Path

def make_config(tmp_path, portal_url=None):
    """Helper to create a temp config.ini with optional portal URL."""
    config = configparser.ConfigParser()
    config['portal'] = {}
    if portal_url is not None:
        config['portal']['url'] = portal_url
    config_file = tmp_path / "config.ini"
    with open(config_file, 'w') as f:
        config.write(f)
    return str(config_file)

def test_portal_url_reads_from_config(tmp_path):
    """portal_url property returns value from config.ini"""
    from avaguard.config import Config
    config_path = make_config(tmp_path, portal_url="http://myserver:9000")
    cfg = Config(config_path)
    assert cfg.portal_url == "http://myserver:9000"

def test_portal_url_fallback_when_key_missing(tmp_path):
    """portal_url returns localhost:8000 when url key not in config"""
    from avaguard.config import Config
    config_path = make_config(tmp_path, portal_url=None)
    cfg = Config(config_path)
    assert cfg.portal_url == "http://localhost:8000"

def test_portal_url_fallback_when_empty(tmp_path):
    """portal_url returns localhost:8000 when url key is empty string"""
    from avaguard.config import Config
    config_path = make_config(tmp_path, portal_url="")
    cfg = Config(config_path)
    assert cfg.portal_url == "http://localhost:8000"

def test_portal_url_accepts_https(tmp_path):
    """portal_url returns https URL correctly"""
    from avaguard.config import Config
    config_path = make_config(tmp_path, portal_url="https://avaguard.company.com")
    cfg = Config(config_path)
    assert cfg.portal_url == "https://avaguard.company.com"

def test_portal_url_strips_whitespace(tmp_path):
    """portal_url strips leading/trailing whitespace"""
    from avaguard.config import Config
    config_path = make_config(tmp_path, portal_url="  http://localhost:8000  ")
    cfg = Config(config_path)
    assert cfg.portal_url == "http://localhost:8000"
