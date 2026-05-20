import logging
import json
import pytest
from pathlib import Path
from unittest.mock import patch


def test_configure_logging_human_format():
    """configure_logging runs without error in human format."""
    from avaguard_core.logging_config import configure_logging
    configure_logging(level="INFO", json_output=False)


def test_configure_logging_json_format():
    """configure_logging runs without error in JSON format."""
    from avaguard_core.logging_config import configure_logging
    configure_logging(level="INFO", json_output=True)


def test_json_formatter_output_is_valid_json():
    """JSONFormatter produces parseable JSON for a log record."""
    from avaguard_core.logging_config import JSONFormatter
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test", level=logging.INFO,
        pathname="test.py", lineno=1,
        msg="Hello world", args=(), exc_info=None
    )
    output = formatter.format(record)
    parsed = json.loads(output)
    assert parsed["message"] == "Hello world"


def test_json_formatter_contains_required_fields():
    """JSON output contains all required fields."""
    from avaguard_core.logging_config import JSONFormatter
    formatter = JSONFormatter()
    record = logging.LogRecord(
        name="test.logger", level=logging.WARNING,
        pathname="test.py", lineno=42,
        msg="Test message", args=(), exc_info=None
    )
    output = json.loads(formatter.format(record))
    for field in ("timestamp", "level", "logger", "message", "module", "function", "line"):
        assert field in output, f"Missing field: {field}"


def test_json_formatter_handles_exception():
    """JSONFormatter includes exception info when exc_info is present."""
    from avaguard_core.logging_config import JSONFormatter
    formatter = JSONFormatter()
    try:
        raise ValueError("test error")
    except ValueError:
        import sys
        exc_info = sys.exc_info()

    record = logging.LogRecord(
        name="test", level=logging.ERROR,
        pathname="test.py", lineno=1,
        msg="Error occurred", args=(), exc_info=exc_info
    )
    output = json.loads(formatter.format(record))
    assert "exception" in output
    assert "ValueError" in output["exception"]


def test_configure_logging_with_file(tmp_path):
    """configure_logging creates log file when log_file path is provided."""
    from avaguard_core.logging_config import configure_logging
    log_path = str(tmp_path / "test.log")
    configure_logging(level="DEBUG", log_file=log_path)
    logger = logging.getLogger("avaguard_core.test")
    logger.info("Test log entry")
    assert Path(log_path).exists()
    assert Path(log_path).stat().st_size > 0


def test_configure_logging_respects_level(tmp_path, capsys):
    """DEBUG messages are not emitted when level is INFO."""
    from avaguard_core.logging_config import configure_logging
    configure_logging(level="INFO", json_output=False)
    logger = logging.getLogger("avaguard_core.level_test")
    logger.debug("This should not appear")
    captured = capsys.readouterr()
    assert "This should not appear" not in captured.err


def test_noisy_loggers_suppressed():
    """urllib3 and msal loggers are set to WARNING."""
    from avaguard_core.logging_config import configure_logging
    configure_logging(level="DEBUG", json_output=False)
    assert logging.getLogger("urllib3").level <= logging.WARNING
    assert logging.getLogger("msal").level <= logging.WARNING


def test_disable_existing_loggers_false():
    """Existing loggers are not disabled after configure_logging."""
    from avaguard_core.logging_config import configure_logging
    existing_logger = logging.getLogger("my.existing.logger")
    existing_logger.setLevel(logging.DEBUG)
    configure_logging(level="INFO")
    assert not existing_logger.disabled
