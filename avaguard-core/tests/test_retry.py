import pytest
from unittest.mock import patch, Mock, MagicMock
import requests
from requests.exceptions import ConnectionError, Timeout, ChunkedEncodingError
from avaguard_core.retry import retry

# --- Helpers ---

@pytest.fixture
def mock_sleep():
    with patch('avaguard_core.retry.time.sleep') as mock:
        yield mock

class MockResponse:
    def __init__(self, status_code, headers=None):
        self.status_code = status_code
        self.headers = headers or {}
        
class HTTPError(Exception):
    def __init__(self, response):
        self.response = response
        
class SimpleError(Exception):
    def __init__(self, status_code):
        self.status_code = status_code

def make_mock(*args, **kwargs):
    m = Mock(*args, **kwargs)
    m.__name__ = "mock_func"
    return m

# --- Tests ---

def test_retry_succeeds_on_first_attempt(mock_sleep):
    mock_func = make_mock(return_value="success")
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 1
    mock_sleep.assert_not_called()

def test_retry_succeeds_after_one_failure(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(503)), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once_with(2.0)

def test_retry_succeeds_after_two_failures(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(500)), HTTPError(MockResponse(500)), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 3
    assert mock_sleep.call_count == 2
    mock_sleep.assert_any_call(2.0)
    mock_sleep.assert_any_call(4.0)

def test_retry_raises_after_max_retries_exceeded(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(500))] * 4)
    decorated = retry(max_retries=3)(mock_func)
    
    with pytest.raises(HTTPError):
        decorated()
        
    assert mock_func.call_count == 4
    assert mock_sleep.call_count == 3

def test_no_retry_on_401(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(401))])
    decorated = retry()(mock_func)
    
    with pytest.raises(HTTPError):
        decorated()
        
    assert mock_func.call_count == 1
    mock_sleep.assert_not_called()

def test_no_retry_on_403(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(403))])
    decorated = retry()(mock_func)
    
    with pytest.raises(HTTPError):
        decorated()
        
    assert mock_func.call_count == 1
    mock_sleep.assert_not_called()

def test_retry_on_429(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(429)), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()

def test_retry_on_500(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(500)), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()

def test_retry_on_503(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(503)), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()

def test_retry_after_header_respected(mock_sleep):
    error_429 = HTTPError(MockResponse(429, headers={'Retry-After': '5.5'}))
    mock_func = make_mock(side_effect=[error_429, "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once_with(5.5)

def test_retry_after_header_capped_at_max_wait(mock_sleep):
    error_429 = HTTPError(MockResponse(429, headers={'Retry-After': '500.0'}))
    mock_func = make_mock(side_effect=[error_429, "success"])
    decorated = retry(max_wait=30.0)(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once_with(30.0)

def test_exponential_backoff_progression(mock_sleep):
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(500)), HTTPError(MockResponse(500)), HTTPError(MockResponse(500)), "success"])
    decorated = retry(max_retries=3, backoff_base=2.0)(mock_func)
    
    assert decorated() == "success"
    assert mock_sleep.call_count == 3
    # attempts: 0 -> 2.0^0 * 2.0 = 2.0
    # attempts: 1 -> 2.0^1 * 2.0 = 4.0
    # attempts: 2 -> 2.0^2 * 2.0 = 8.0
    assert mock_sleep.call_args_list[0][0][0] == 2.0
    assert mock_sleep.call_args_list[1][0][0] == 4.0
    assert mock_sleep.call_args_list[2][0][0] == 8.0

def test_connection_error_is_retried(mock_sleep):
    mock_func = make_mock(side_effect=[ConnectionError("Disconnected"), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()

def test_timeout_is_retried(mock_sleep):
    mock_func = make_mock(side_effect=[Timeout("Too slow"), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()

def test_non_retryable_exception_raises_immediately(mock_sleep):
    mock_func = make_mock(side_effect=[ValueError("Bad logic")])
    decorated = retry()(mock_func)
    
    with pytest.raises(ValueError):
        decorated()
        
    assert mock_func.call_count == 1
    mock_sleep.assert_not_called()

def test_retry_preserves_function_return_value(mock_sleep):
    expected_result = {"user_count": 5}
    mock_func = make_mock(side_effect=[HTTPError(MockResponse(500)), expected_result])
    decorated = retry()(mock_func)
    
    assert decorated() == expected_result

def test_extract_status_code_from_response(mock_sleep):
    # Verify inner behavior using public behavior by checking standard exception class extraction
    mock_func = make_mock(side_effect=[SimpleError(429), "success"])
    decorated = retry()(mock_func)
    
    assert decorated() == "success"
    assert mock_func.call_count == 2
    mock_sleep.assert_called_once()
