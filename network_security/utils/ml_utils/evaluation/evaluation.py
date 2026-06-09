import sys

from sklearn.metrics import f1_score
from sklearn.model_selection import GridSearchCV

from network_security.exception.exception import NetworkSecurityException


def evaluate_models(X_train: object, y_train: object, X_test: object, y_test: object, models: dict, param: dict) -> dict:
    try:
        report = {}

        for i in range(len(list(models))):
            model = list(models.values())[i]
            para = param[list(models.keys())[i]]

            gs = GridSearchCV(model, para, cv=3)
            gs.fit(X_train, y_train)

            model.set_params(**gs.best_params_)
            model.fit(X_train, y_train)

            # model.fit(X_train, y_train)  # Train model

            y_test_pred = model.predict(X_test)

            test_model_score = f1_score(y_test, y_test_pred, average="binary")

            report[list(models.keys())[i]] = test_model_score

        return report

    except Exception as e:
        raise NetworkSecurityException(e, sys)
