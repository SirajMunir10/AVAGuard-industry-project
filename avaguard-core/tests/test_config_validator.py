import pytest
from pathlib import Path
from avaguard_core.config_validator import ConfigValidator, validate_config, ValidationSeverity

def test_valid_fully_operational_config(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""
[Azure]
tenant_id = 12345678-1234-1234-1234-1234567890ab
client_id = 12345678-1234-1234-1234-1234567890ab
client_secret = aabbccddeeffgghhiijjkkllmmnnoopp
[General]
mock_data_file = mock.json
[portal]
url = https://portal.com
""")
    # Touch mock json so the path triggers valid
    (tmp_path / "mock.json").write_text("{}")
    
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is True
    assert report.has_errors() is False
    assert report.has_warnings() is False
    assert report.normalized_config['tenant_id'] == "12345678-1234-1234-1234-1234567890ab"

def test_empty_tenant_fails_live(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = \nclient_id = 12345678-1234-1234-1234-1234567890ab\nclient_secret = aabbccddeeffgghhiijjkkllmmnnoopp""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False
    assert any(e.field == "tenant_id" for e in report.get_errors())

def test_placeholder_tenant_fails_live(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = YOUR_TENANT_ID""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False
    assert any(e.field == "tenant_id" for e in report.get_errors())

def test_invalid_guid_format_fails_live(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = 123-abc""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False

def test_short_secret_fails_live(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = 12345678-1234-1234-1234-1234567890ab\nclient_id = 12345678-1234-1234-1234-1234567890ab\nclient_secret = tooshort""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False
    assert any(e.field == "client_secret" for e in report.get_errors())

def test_secret_with_spaces_fails_live(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = 12345678-1234-1234-1234-1234567890ab\nclient_id = 12345678-1234-1234-1234-1234567890ab\nclient_secret = a b c d e f g h i j k l m n o p q r s""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False

def test_explicit_missing_mock_file_warns(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[General]\nmock_data_file = doesnotexist.json""")
    report = validate_config(str(config_file))
    assert report.has_warnings() is True
    assert any(w.field == "mock_data_file" for w in report.get_warnings())

def test_default_missing_mock_file_silent(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[General]""")
    report = validate_config(str(config_file))
    assert not any(w.field == "mock_data_file" for w in report.get_warnings())
    
    # In GitHub/prod, this should be tested. Default falls back safely.
    assert 'mock_data_file' in report.normalized_config

def test_invalid_portal_url_warns(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[portal]\nurl = ftp://bad.com""")
    report = validate_config(str(config_file))
    assert any(w.field == "portal_url" for w in report.get_warnings())

def test_empty_portal_url_info(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[portal]\nurl = """)
    report = validate_config(str(config_file))
    infos = [r for r in report.results if r.severity == ValidationSeverity.INFO]
    assert any(i.field == "portal_url" for i in infos)

def test_mock_validity_persists_on_live_failure(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = bad""")
    report = validate_config(str(config_file))
    assert report.is_valid_for_live is False
    assert report.is_valid_for_mock is True

def test_missing_config_file_fails_gracefully(tmp_path):
    bad_path = str(tmp_path / "nonexistent.ini")
    report = validate_config(bad_path)
    assert report.is_valid_for_live is False
    assert report.has_errors() is True
    assert any(e.field == "config_file" for e in report.get_errors())

def test_has_and_get_methods(tmp_path):
    config_file = tmp_path / "config.ini"
    config_file.write_text("""[Azure]\ntenant_id = bad\nclient_id = 12345678-1234-1234-1234-1234567890ab\nclient_secret = aabbccddeeffgghhiijjkkllmmnnoopp\n[portal]\nurl = ftp://fail.com""")
    report = validate_config(str(config_file))
    assert report.has_errors() is True
    assert report.has_warnings() is True
    assert len(report.get_errors()) == 1
    assert len(report.get_warnings()) == 1
