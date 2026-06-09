from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest
import yaml

from network_security.components.data_validation import DataValidation
from network_security.entity.artifact_entity import DataValidationArtifact
from network_security.exception.exception import NetworkSecurityException


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def validation_config(tmp_path: Path):
    config = MagicMock()
    config.drift_report_file_path = str(tmp_path / "drift_report" / "report.yaml")
    config.valid_train_file_path  = str(tmp_path / "validated" / "train.csv")
    config.valid_test_file_path   = str(tmp_path / "validated" / "test.csv")
    return config


@pytest.fixture
def ingestion_artifact(tmp_path: Path):
    artifact = MagicMock()
    artifact.trained_file_path = str(tmp_path / "train.csv")
    artifact.test_file_path    = str(tmp_path / "test.csv")
    return artifact


@pytest.fixture
def validator(validation_config, ingestion_artifact):
    with patch(
        "network_security.components.data_validation.read_yaml_file",
        return_value={
            "columns": [{"a": "int64"}, {"b": "int64"}],
            "numerical_columns": ["a", "b"],
        },
    ):
        return DataValidation(
            data_ingestion_artifact=ingestion_artifact,
            data_validation_config=validation_config,
        )


@pytest.fixture
def identical_dataframes():
    """Two DataFrames drawn from the same distribution — KS test should not
    detect drift (p-value well above 0.05)."""
    rng = np.random.default_rng(0)
    data = rng.normal(loc=0.0, scale=1.0, size=(300, 2))
    cols = ["a", "b"]
    return pd.DataFrame(data, columns=cols), pd.DataFrame(data, columns=cols)


@pytest.fixture
def drifted_dataframes():
    """Two DataFrames from clearly different distributions — KS test should
    detect drift (p-value well below 0.05)."""
    rng = np.random.default_rng(42)
    base    = pd.DataFrame(rng.normal(0.0, 1.0, (300, 2)), columns=["a", "b"])
    current = pd.DataFrame(rng.normal(10.0, 1.0, (300, 2)), columns=["a", "b"])
    return base, current


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_detect_drift_returns_true_when_no_drift(validator, identical_dataframes):
    """detect_dataset_drift must return True when distributions are identical.

    BUG-09: the function declared -> bool but never returned anything,
    so validation_status was always None."""
    base_df, current_df = identical_dataframes

    result = validator.detect_dataset_drift(base_df, current_df)

    assert result is True, (
        f"Expected True (no drift), got {result!r}. "
        "detect_dataset_drift may still be returning None implicitly."
    )
    assert isinstance(result, bool), f"Return type must be bool, got {type(result)}"


def test_detect_drift_returns_false_when_drift_present(validator, drifted_dataframes):
    """detect_dataset_drift must return False when distributions clearly differ."""
    base_df, current_df = drifted_dataframes

    result = validator.detect_dataset_drift(base_df, current_df)

    assert result is False, (
        f"Expected False (drift detected), got {result!r}."
    )
    assert isinstance(result, bool), f"Return type must be bool, got {type(result)}"


def test_detect_drift_writes_report_file(validator, identical_dataframes, validation_config):
    """detect_dataset_drift must create the drift report YAML file."""
    base_df, current_df = identical_dataframes

    validator.detect_dataset_drift(base_df, current_df)

    report_path = Path(validation_config.drift_report_file_path)
    assert report_path.exists(), "Drift report file was not created"

    report = yaml.safe_load(report_path.read_text())
    assert "a" in report
    assert "b" in report
    assert "p_value" in report["a"]
    assert "drift_status" in report["a"]


def test_detect_drift_calls_write_yaml_once(validator, identical_dataframes):
    """write_yaml_file must be called exactly once per invocation.

    BUG-08/BUG-09: the function had two consecutive write_yaml_file calls,
    duplicating the report content."""
    base_df, current_df = identical_dataframes

    with patch(
        "network_security.components.data_validation.write_yaml_file"
    ) as mock_write:
        validator.detect_dataset_drift(base_df, current_df)

    assert mock_write.call_count == 1, (
        f"write_yaml_file was called {mock_write.call_count} times — expected exactly 1."
    )


# ---------------------------------------------------------------------------
# Fixtures for BUG-10: hard gate tests
# ---------------------------------------------------------------------------

SCHEMA_3_COLS = {
    "columns": [{"a": "int64"}, {"b": "int64"}, {"c": "int64"}],
    "numerical_columns": ["a", "b", "c"],
}

VALID_DF = pd.DataFrame({"a": [1, 2, 3], "b": [4, 5, 6], "c": [0, 1, 0]})


def _make_validator(tmp_path: Path, schema: dict) -> tuple:
    """Return (validator, ingestion_artifact, validation_config) with real CSVs."""
    train_path = tmp_path / "train.csv"
    test_path  = tmp_path / "test.csv"
    VALID_DF.to_csv(train_path, index=False)
    VALID_DF.to_csv(test_path, index=False)

    ingestion_artifact = MagicMock()
    ingestion_artifact.trained_file_path = str(train_path)
    ingestion_artifact.test_file_path    = str(test_path)

    validation_config = MagicMock()
    validation_config.drift_report_file_path = str(tmp_path / "drift" / "report.yaml")
    validation_config.valid_train_file_path  = str(tmp_path / "validated" / "train.csv")
    validation_config.valid_test_file_path   = str(tmp_path / "validated" / "test.csv")

    with patch(
        "network_security.components.data_validation.read_yaml_file",
        return_value=schema,
    ):
        v = DataValidation(
            data_ingestion_artifact=ingestion_artifact,
            data_validation_config=validation_config,
        )
    return v, ingestion_artifact, validation_config


# ---------------------------------------------------------------------------
# Tests — BUG-10: initiate_data_validation as hard gate
# ---------------------------------------------------------------------------

def test_initiate_raises_when_train_has_wrong_column_count(tmp_path: Path):
    """initiate_data_validation must raise NetworkSecurityException when the
    train CSV has fewer columns than the schema requires.

    BUG-10: previously only logged and continued silently."""
    schema_4_cols = {
        "columns": [{"a": "int64"}, {"b": "int64"}, {"c": "int64"}, {"d": "int64"}],
        "numerical_columns": ["a", "b", "c", "d"],
    }
    validator, _, _ = _make_validator(tmp_path, schema_4_cols)

    # VALID_DF has 3 columns; schema expects 4 → column count fails for train
    with pytest.raises(NetworkSecurityException) as exc_info:
        validator.initiate_data_validation()

    assert "Train dataframe does not contain all required columns" in str(exc_info.value)


def test_initiate_raises_when_test_has_wrong_column_count(tmp_path: Path):
    """initiate_data_validation must raise NetworkSecurityException when the
    test CSV has fewer columns than the schema requires."""
    schema_4_cols = {
        "columns": [{"a": "int64"}, {"b": "int64"}, {"c": "int64"}, {"d": "int64"}],
        "numerical_columns": ["a", "b", "c", "d"],
    }
    validator, ingestion_artifact, _ = _make_validator(tmp_path, schema_4_cols)

    # Override train to have 4 columns so only test fails
    good_train = tmp_path / "good_train.csv"
    pd.DataFrame({"a": [1], "b": [2], "c": [3], "d": [4]}).to_csv(good_train, index=False)
    ingestion_artifact.trained_file_path = str(good_train)

    with pytest.raises(NetworkSecurityException) as exc_info:
        validator.initiate_data_validation()

    assert "Test dataframe does not contain all required columns" in str(exc_info.value)


def test_initiate_raises_when_drift_is_detected(tmp_path: Path):
    """initiate_data_validation must raise NetworkSecurityException when
    detect_dataset_drift returns False (drift found).

    BUG-10: previously ignored the drift result and continued."""
    validator, _, _ = _make_validator(tmp_path, SCHEMA_3_COLS)

    with patch.object(validator, "detect_dataset_drift", return_value=False):
        with pytest.raises(NetworkSecurityException) as exc_info:
            validator.initiate_data_validation()

    assert "drift" in str(exc_info.value).lower()


def test_initiate_returns_artifact_with_true_when_all_checks_pass(tmp_path: Path):
    """initiate_data_validation must return DataValidationArtifact with
    validation_status=True when all checks pass (no drift, correct schema)."""
    validator, _, _ = _make_validator(tmp_path, SCHEMA_3_COLS)

    with patch.object(validator, "detect_dataset_drift", return_value=True):
        artifact = validator.initiate_data_validation()

    assert isinstance(artifact, DataValidationArtifact)
    assert artifact.validation_status is True
