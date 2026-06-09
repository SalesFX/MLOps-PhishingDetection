import pickle
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
from sklearn.impute import KNNImputer
from sklearn.pipeline import Pipeline

from network_security.utils.ml_utils.model.estimator import NetworkModel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fake_transformation_artifact(tmp_path: Path):
    """Real preprocessor + numpy arrays written to tmp_path.
    No MongoDB or pipeline execution required."""
    preprocessor = Pipeline([("imputer", KNNImputer(n_neighbors=3))])
    rng = np.random.default_rng(0)
    preprocessor.fit(rng.standard_normal((50, 4)))

    preprocessor_path = tmp_path / "preprocessing.pkl"
    with preprocessor_path.open("wb") as f:
        pickle.dump(preprocessor, f)

    train_arr = np.c_[rng.standard_normal((50, 4)), rng.integers(0, 2, 50)]
    test_arr  = np.c_[rng.standard_normal((20, 4)), rng.integers(0, 2, 20)]

    train_path = tmp_path / "train.npy"
    test_path  = tmp_path / "test.npy"
    np.save(train_path, train_arr)
    np.save(test_path, test_arr)

    artifact = MagicMock()
    artifact.transformed_object_file_path = str(preprocessor_path)
    artifact.transformed_train_file_path  = str(train_path)
    artifact.transformed_test_file_path   = str(test_path)
    return artifact


@pytest.fixture
def fake_trainer_config(tmp_path: Path):
    config = MagicMock()
    config.trained_model_file_path = str(tmp_path / "model_trainer" / "model.pkl")
    config.expected_accuracy = 0.0
    config.overfitting_underfitting_threshold = 0.05
    config.min_f1_score = 0.0       # gate disabled by default — set per-test for gate tests
    config.min_recall_score = 0.0
    return config


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_saved_artifact_is_network_model_instance(
    fake_trainer_config, fake_transformation_artifact
):
    """The artifact at trained_model_file_path must be an instance of NetworkModel,
    not the class itself. BUG-02: save_object was called with obj=NetworkModel
    (the class) instead of obj=network_model (the fitted instance)."""
    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow"):
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        trainer.initiate_model_trainer()

    artifact_path = fake_trainer_config.trained_model_file_path
    assert Path(artifact_path).exists(), "Artifact file was not created"

    with open(artifact_path, "rb") as f:
        saved_object = pickle.load(f)

    assert isinstance(saved_object, NetworkModel), (
        f"Expected an instance of NetworkModel, got {type(saved_object)}. "
        "model_trainer.py likely still saves obj=NetworkModel (the class) "
        "instead of obj=network_model (the fitted instance)."
    )


def test_saved_network_model_can_predict(
    fake_trainer_config, fake_transformation_artifact
):
    """A NetworkModel loaded from the artifact must call .predict() without
    raising TypeError — which would happen if the class itself was pickled."""
    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow"):
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        trainer.initiate_model_trainer()

    with open(fake_trainer_config.trained_model_file_path, "rb") as f:
        saved_model = pickle.load(f)

    rng = np.random.default_rng(99)
    X_sample = rng.standard_normal((5, 4))

    predictions = saved_model.predict(X_sample)
    assert predictions is not None
    assert len(predictions) == 5


def test_mlflow_single_run_logs_all_metrics_and_model(
    fake_trainer_config, fake_transformation_artifact
):
    """A single mlflow.start_run() must be opened per training run and must
    contain train/test metrics, model params, and the model artifact.

    Previously track_mlflow was called twice — once for train metrics and once
    for test metrics — creating two separate runs. Now one run holds everything."""
    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow") as mock_mlflow:
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        trainer.initiate_model_trainer()

    # Exactly one run opened
    assert mock_mlflow.start_run.call_count == 1, (
        f"Expected exactly 1 mlflow.start_run() call, got {mock_mlflow.start_run.call_count}."
    )

    # Model artifact logged exactly once
    assert mock_mlflow.sklearn.log_model.call_count == 1, (
        f"Expected mlflow.sklearn.log_model to be called once, "
        f"got {mock_mlflow.sklearn.log_model.call_count}."
    )
    _, log_model_kwargs = mock_mlflow.sklearn.log_model.call_args
    log_model_args = mock_mlflow.sklearn.log_model.call_args[0]
    artifact_path = log_model_args[1] if len(log_model_args) > 1 else log_model_kwargs.get("artifact_path")
    assert artifact_path == "model"

    # Collect all metric names logged
    logged_metrics = {
        call.args[0]
        for call in mock_mlflow.log_metric.call_args_list
    }
    for expected in ("train_f1", "train_precision", "train_recall",
                     "test_f1", "test_precision", "test_recall"):
        assert expected in logged_metrics, (
            f"Expected metric '{expected}' to be logged, found: {logged_metrics}"
        )

    # model_name parameter must be logged
    logged_params = {
        call.args[0]: call.args[1]
        for call in mock_mlflow.log_param.call_args_list
        if call.args
    }
    assert "model_name" in logged_params, (
        f"Expected 'model_name' param to be logged, found: {list(logged_params.keys())}"
    )


# ---------------------------------------------------------------------------
# Quality Gate Tests
# ---------------------------------------------------------------------------

from network_security.exception.exception import NetworkSecurityException  # noqa: E402


def test_quality_gate_saves_model_when_metrics_pass(
    fake_trainer_config, fake_transformation_artifact
):
    """When both F1 and Recall are above the configured thresholds, the model
    artifact must be written to disk."""
    fake_trainer_config.min_f1_score = 0.0
    fake_trainer_config.min_recall_score = 0.0

    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow"):
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        trainer.initiate_model_trainer()

    assert Path(fake_trainer_config.trained_model_file_path).exists(), (
        "Model artifact was not saved even though quality gate thresholds were met."
    )


def test_quality_gate_raises_when_f1_below_threshold(
    fake_trainer_config, fake_transformation_artifact
):
    """When F1 score is below min_f1_score, initiate_model_trainer must raise
    NetworkSecurityException and must NOT write the model to disk."""
    fake_trainer_config.min_f1_score = 0.9999   # no real model achieves this on the synthetic data
    fake_trainer_config.min_recall_score = 0.0

    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow"):
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        with pytest.raises(NetworkSecurityException) as exc_info:
            trainer.initiate_model_trainer()

    assert "F1" in str(exc_info.value), (
        "Exception message must mention F1 when the F1 gate is the one that failed."
    )
    assert not Path(fake_trainer_config.trained_model_file_path).exists(), (
        "Model artifact must NOT be saved when the quality gate rejects the model."
    )


def test_quality_gate_raises_when_recall_below_threshold(
    fake_trainer_config, fake_transformation_artifact
):
    """When Recall score is below min_recall_score, initiate_model_trainer must
    raise NetworkSecurityException and must NOT write the model to disk."""
    fake_trainer_config.min_f1_score = 0.0
    fake_trainer_config.min_recall_score = 0.9999   # no real model achieves this on the synthetic data

    from network_security.components.model_trainer import ModelTrainer

    with patch("network_security.components.model_trainer.mlflow"):
        trainer = ModelTrainer(
            model_trainer_config=fake_trainer_config,
            data_transformation_artifact=fake_transformation_artifact,
        )
        with pytest.raises(NetworkSecurityException) as exc_info:
            trainer.initiate_model_trainer()

    assert "Recall" in str(exc_info.value), (
        "Exception message must mention Recall when the Recall gate is the one that failed."
    )
    assert not Path(fake_trainer_config.trained_model_file_path).exists(), (
        "Model artifact must NOT be saved when the quality gate rejects the model."
    )
