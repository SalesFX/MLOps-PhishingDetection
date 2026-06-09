import os
import sys
from pathlib import Path

import dagshub
import mlflow
from sklearn.ensemble import (
    AdaBoostClassifier,
    GradientBoostingClassifier,
    RandomForestClassifier,
)
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier

from network_security.entity.artifact_entity import (
    DataTransformationArtifact,
    ModelTrainerArtifact,
)
from network_security.entity.config_entity import ModelTrainerConfig
from network_security.exception.exception import NetworkSecurityException
from network_security.logging.logger import logging
from network_security.utils.main_utils.utils import (
    load_numpy_array_data,
    load_object,
    save_object,
)
from network_security.utils.ml_utils.evaluation.evaluation import evaluate_models
from network_security.utils.ml_utils.metric.classification_metric import (
    get_classification_score,
)
from network_security.utils.ml_utils.model.estimator import NetworkModel

_dagshub_owner = os.getenv("DAGSHUB_REPO_OWNER")
_dagshub_repo = os.getenv("DAGSHUB_REPO_NAME")

if _dagshub_owner and _dagshub_repo:
    dagshub.init(repo_owner=_dagshub_owner, repo_name=_dagshub_repo, mlflow=True)
else:
    mlflow.set_tracking_uri(os.getenv("MLFLOW_TRACKING_URI", "mlruns"))


class ModelTrainer:
    def __init__(
        self,
        model_trainer_config: ModelTrainerConfig,
        data_transformation_artifact: DataTransformationArtifact,
    ) -> None:
        try:
            self.model_trainer_config = model_trainer_config
            self.data_transformation_artifact = data_transformation_artifact
        except Exception as e:
            raise NetworkSecurityException(e, sys)

    def track_mlflow(
        self,
        best_model: object,
        best_model_name: str,
        train_metric: object,
        test_metric: object,
    ) -> None:
        with mlflow.start_run():
            mlflow.log_param("model_name", best_model_name)
            mlflow.log_param("min_f1_score", self.model_trainer_config.min_f1_score)
            mlflow.log_param("min_recall_score", self.model_trainer_config.min_recall_score)

            try:
                mlflow.log_params(best_model.get_params())
            except Exception:
                pass

            mlflow.log_metric("train_f1", train_metric.f1_score)
            mlflow.log_metric("train_precision", train_metric.precision_score)
            mlflow.log_metric("train_recall", train_metric.recall_score)

            mlflow.log_metric("test_f1", test_metric.f1_score)
            mlflow.log_metric("test_precision", test_metric.precision_score)
            mlflow.log_metric("test_recall", test_metric.recall_score)

            mlflow.sklearn.log_model(best_model, "model")

    def train_model(
        self,
        X_train: object,
        y_train: object,
        X_test: object,
        y_test: object,
    ) -> ModelTrainerArtifact:
        models = {
            "Random Forest": RandomForestClassifier(verbose=1),
            "Decision Tree": DecisionTreeClassifier(),
            "Gradient Boosting": GradientBoostingClassifier(verbose=1),
            "Logistic Regression": LogisticRegression(verbose=1),
            "AdaBoost": AdaBoostClassifier(),
        }
        params = {
            "Decision Tree": {
                "criterion": ["gini", "entropy", "log_loss"],
                # "splitter": ["best", "random"],
                # "max_features": ["sqrt", "log2"],
            },
            "Random Forest": {
                # "criterion": ["gini", "entropy", "log_loss"],
                # "max_features": ["sqrt", "log2", None],
                "n_estimators": [8, 16, 32, 128, 256],
            },
            "Gradient Boosting": {
                # "loss": ["log_loss", "exponential"],
                "learning_rate": [0.1, 0.01, 0.05, 0.001],
                "subsample": [0.6, 0.7, 0.75, 0.85, 0.9],
                # "criterion": ["squared_error", "friedman_mse"],
                # "max_features": ["auto", "sqrt", "log2"],
                "n_estimators": [8, 16, 32, 64, 128, 256],
            },
            "Logistic Regression": {},
            "AdaBoost": {
                "learning_rate": [0.1, 0.01, 0.001],
                "n_estimators": [8, 16, 32, 64, 128, 256],
            },
        }
        model_report: dict = evaluate_models(
            X_train=X_train,
            y_train=y_train,
            X_test=X_test,
            y_test=y_test,
            models=models,
            param=params,
        )

        ## To get best model score from dict
        best_model_score = max(sorted(model_report.values()))

        ## To get best model name from dict
        best_model_name = list(model_report.keys())[
            list(model_report.values()).index(best_model_score)
        ]
        best_model = models[best_model_name]
        y_train_pred = best_model.predict(X_train)

        classification_train_metric = get_classification_score(
            y_true=y_train,
            y_pred=y_train_pred,
        )

        y_test_pred = best_model.predict(X_test)
        classification_test_metric = get_classification_score(
            y_true=y_test,
            y_pred=y_test_pred,
        )

        self.track_mlflow(
            best_model,
            best_model_name,
            classification_train_metric,
            classification_test_metric,
        )

        if classification_test_metric.f1_score < self.model_trainer_config.min_f1_score:
            raise ValueError(
                f"Model quality gate failed: F1 score "
                f"{classification_test_metric.f1_score:.4f} is below the minimum "
                f"threshold of {self.model_trainer_config.min_f1_score}."
            )

        if classification_test_metric.recall_score < self.model_trainer_config.min_recall_score:
            raise ValueError(
                f"Model quality gate failed: Recall score "
                f"{classification_test_metric.recall_score:.4f} is below the minimum "
                f"threshold of {self.model_trainer_config.min_recall_score}."
            )

        preprocessor = load_object(
            file_path=self.data_transformation_artifact.transformed_object_file_path,
        )
        model_dir_path = Path(self.model_trainer_config.trained_model_file_path).parent
        model_dir_path.mkdir(parents=True, exist_ok=True)

        network_model = NetworkModel(preprocessor=preprocessor, model=best_model)
        save_object(self.model_trainer_config.trained_model_file_path, obj=network_model)

        ## Model pusher
        save_object("final_model/model.pkl", best_model)

        ## Model Trainer Artifact
        model_trainer_artifact = ModelTrainerArtifact(
            trained_model_file_path=self.model_trainer_config.trained_model_file_path,
            train_metric_artifact=classification_train_metric,
            test_metric_artifact=classification_test_metric,
        )
        logging.info(f"Model trainer artifact: {model_trainer_artifact}")
        return model_trainer_artifact

    def initiate_model_trainer(self) -> ModelTrainerArtifact:
        try:
            train_file_path = (
                self.data_transformation_artifact.transformed_train_file_path
            )
            test_file_path = (
                self.data_transformation_artifact.transformed_test_file_path
            )

            # Loading training array and testing array
            train_arr = load_numpy_array_data(train_file_path)
            test_arr = load_numpy_array_data(test_file_path)

            x_train, y_train, x_test, y_test = (
                train_arr[:, :-1],
                train_arr[:, -1],
                test_arr[:, :-1],
                test_arr[:, -1],
            )

            model_trainer_artifact = self.train_model(x_train, y_train, x_test, y_test)
            return model_trainer_artifact

        except Exception as e:
            raise NetworkSecurityException(e, sys)
