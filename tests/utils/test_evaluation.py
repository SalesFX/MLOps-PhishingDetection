import numpy as np
import pytest
from sklearn.tree import DecisionTreeClassifier

from network_security.utils.ml_utils.evaluation.evaluation import evaluate_models


@pytest.fixture
def binary_classification_data():
    rng = np.random.default_rng(42)
    X_train = rng.standard_normal((100, 4))
    y_train = rng.integers(0, 2, size=100)
    X_test = rng.standard_normal((40, 4))
    y_test = rng.integers(0, 2, size=40)
    return X_train, y_train, X_test, y_test


def test_evaluate_models_returns_f1_not_r2(binary_classification_data):
    """evaluate_models must score models by F1, not R². R² on binary outputs
    produces values in (-inf, 1] and is often negative for bad classifiers,
    while F1 is always in [0, 1]."""
    X_train, y_train, X_test, y_test = binary_classification_data

    models = {"DecisionTree": DecisionTreeClassifier(random_state=0)}
    params = {"DecisionTree": {"criterion": ["gini"]}}

    report = evaluate_models(X_train, y_train, X_test, y_test, models, params)

    assert "DecisionTree" in report
    score = report["DecisionTree"]

    # F1 is always in [0.0, 1.0] — R² is not bounded below
    assert 0.0 <= score <= 1.0, (
        f"Score {score:.4f} is outside [0, 1]. "
        "evaluate_models is likely still using r2_score instead of f1_score."
    )


def test_evaluate_models_report_keys_match_model_names(binary_classification_data):
    """report dict keys must exactly match the model names passed in."""
    X_train, y_train, X_test, y_test = binary_classification_data

    models = {
        "ModelA": DecisionTreeClassifier(random_state=0),
        "ModelB": DecisionTreeClassifier(max_depth=2, random_state=1),
    }
    params = {
        "ModelA": {"criterion": ["gini"]},
        "ModelB": {"criterion": ["entropy"]},
    }

    report = evaluate_models(X_train, y_train, X_test, y_test, models, params)

    assert set(report.keys()) == {"ModelA", "ModelB"}
    for name, score in report.items():
        assert 0.0 <= score <= 1.0, f"{name} score {score:.4f} outside [0, 1]"


def test_evaluate_models_best_model_selected_by_f1(binary_classification_data):
    """The model with the highest F1 should have the highest score in the report.
    This ensures model selection downstream uses F1, not R²."""
    X_train, y_train, X_test, y_test = binary_classification_data

    # max_depth=None (full tree) typically fits better than max_depth=1 (stump)
    models = {
        "FullTree": DecisionTreeClassifier(random_state=0),
        "Stump": DecisionTreeClassifier(max_depth=1, random_state=0),
    }
    params = {
        "FullTree": {"criterion": ["gini"]},
        "Stump": {"criterion": ["gini"]},
    }

    report = evaluate_models(X_train, y_train, X_test, y_test, models, params)

    # Both scores must be valid F1 values
    for name, score in report.items():
        assert 0.0 <= score <= 1.0, f"{name} returned score {score:.4f} — not a valid F1"
