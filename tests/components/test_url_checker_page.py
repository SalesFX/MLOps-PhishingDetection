from fastapi.testclient import TestClient

from app import app

client = TestClient(app)


def test_url_checker_page_returns_200() -> None:
    response = client.get("/url-checker")
    assert response.status_code == 200


def test_url_checker_page_contains_title() -> None:
    response = client.get("/url-checker")
    assert "Phishing URL Detector" in response.text


def test_url_checker_page_contains_form_elements() -> None:
    response = client.get("/url-checker")
    assert "url-input" in response.text
    assert "verify-btn" in response.text
    assert "predict-url" in response.text


def test_url_checker_page_contains_accessibility_elements() -> None:
    response = client.get("/url-checker")
    # badge texts must be explicit, not color-only
    assert "PHISHING" in response.text
    assert "LEGÍTIMA" in response.text
    # loading has role=status
    assert 'role="status"' in response.text
    # error box has role=alert
    assert 'role="alert"' in response.text
