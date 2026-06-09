"""Tests for the POST /predict-url endpoint."""
import io
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from fastapi.testclient import TestClient

from app import app

client = TestClient(app)

_LEGITIMATE_PRED = np.array([1])
_PHISHING_PRED = np.array([0])
_PROBA = np.array([[0.02, 0.98]])


def _make_mocks(mock_load_object: MagicMock, mock_network_model_cls: MagicMock, y_pred: np.ndarray = _LEGITIMATE_PRED) -> MagicMock:
    """Wire up load_object and NetworkModel mocks; return the instance mock."""
    mock_load_object.side_effect = [MagicMock(), MagicMock()]
    instance = MagicMock()
    instance.predict.return_value = y_pred
    instance.predict_proba.return_value = _PROBA
    mock_network_model_cls.return_value = instance
    return instance


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_returns_200_with_valid_url(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_response_has_30_features(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200
    assert len(response.json()["features"]) == 30


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_feature_vector_has_30_positions(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200
    assert len(response.json()["feature_vector"]) == 30


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_string_features_are_calculated(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    # 192.168.1.1 is an IP address — having_IP_Address must return -1 (not fallback 0)
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://192.168.1.1/login"})
    assert response.status_code == 200
    features = response.json()["features"]
    assert features["having_IP_Address"] == -1


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_fallback_features_are_zero(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200
    features = response.json()["features"]
    # SSLfinal_State is not implemented yet and must use the fallback value 0
    assert features["SSLfinal_State"] == 0


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_warnings_present_for_fallback_features(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200
    body = response.json()
    # 20 features use fallback; each should appear in warnings
    assert len(body["warnings"]) == 20
    assert body["extraction_status"]["fallback_features"] == 20
    assert body["extraction_status"]["calculated_features"] == 10


def test_predict_url_empty_url_returns_422() -> None:
    response = client.post("/predict-url", json={"url": ""})
    assert response.status_code == 422


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_url_without_scheme_is_accepted(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "example.com"})
    assert response.status_code == 200


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_csv_endpoint_still_works(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls, y_pred=np.array([1, 0]))
    from network_security.utils.feature_extractor import FEATURE_ORDER
    header = ",".join(FEATURE_ORDER)
    row1 = ",".join(["1"] * 30)
    row2 = ",".join(["0"] * 30)
    csv_content = f"{header}\n{row1}\n{row2}\n".encode()
    response = client.post(
        "/predict",
        files={"file": ("test.csv", io.BytesIO(csv_content), "text/csv")},
    )
    # The endpoint renders an HTML template; 200 means it processed correctly
    assert response.status_code == 200


@patch("app.NetworkModel")
@patch("app.load_object")
def test_predict_url_prediction_is_phishing_or_legitimate(mock_load_object: MagicMock, mock_network_model_cls: MagicMock) -> None:
    _make_mocks(mock_load_object, mock_network_model_cls)
    response = client.post("/predict-url", json={"url": "http://google.com"})
    assert response.status_code == 200
    assert response.json()["prediction"] in ("phishing", "legitimate")
