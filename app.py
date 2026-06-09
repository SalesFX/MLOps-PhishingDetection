import os
import sys
from pathlib import Path
from typing import Annotated

import certifi
import pandas as pd
from dotenv import load_dotenv
from fastapi import FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from fastapi.templating import Jinja2Templates
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
from pydantic import BaseModel, Field
from starlette.responses import RedirectResponse
from starlette.templating import _TemplateResponse
from uvicorn import run as app_run

from network_security.constant.training_pipeline import (
    DATA_INGESTION_COLLECTION_NAME,
    DATA_INGESTION_DATABASE_NAME,
)
from network_security.exception.exception import NetworkSecurityException
from network_security.logging.logger import logging
from network_security.pipeline.training_pipeline import TrainingPipeline
from network_security.utils.feature_extractor import (
    FEATURE_ORDER,
    URLFeatureExtractor,
    build_feature_vector,
)
from network_security.utils.main_utils.utils import load_object
from network_security.utils.ml_utils.model.estimator import NetworkModel

ca = certifi.where()


load_dotenv()

mongo_db_url: str | None = os.getenv("MONGO_DB_URL")
if not mongo_db_url:
    raise ValueError("MONGO_DB_URL environment variable is not set.")

client = MongoClient(mongo_db_url, server_api=ServerApi("1"), tlsCAFile=ca)


database = client[DATA_INGESTION_DATABASE_NAME]
collection = database[DATA_INGESTION_COLLECTION_NAME]

app = FastAPI()
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


templates = Jinja2Templates(directory="./templates")


@app.get("/", tags=["authentication"])
async def index() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/url-checker")
async def url_checker_page(request: Request) -> _TemplateResponse:
    return templates.TemplateResponse(request=request, name="url_checker.html", context={})


@app.get("/train")
async def train_route() -> Response:
    try:
        train_pipeline = TrainingPipeline()
        train_pipeline.run_pipeline()
        return Response("Training is successful")
    except Exception as e:
        raise NetworkSecurityException(e, sys)


@app.post("/predict")
async def predict_route(request: Request, file: Annotated[UploadFile, File()] = ...) -> _TemplateResponse:
    try:
        df = pd.read_csv(file.file)
        # print(df)
        preprocesor = load_object("final_model/preprocessor.pkl")
        final_model = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocesor, model=final_model)
        logging.debug("predict_route first row: %s", df.iloc[0])
        y_pred = network_model.predict(df)
        logging.debug("predict_route predictions: %s", y_pred)
        df["predicted_column"] = y_pred
        logging.debug("predict_route predicted_column: %s", df["predicted_column"])
        # df['predicted_column'].replace(-1, 0)
        # return df.to_json()
        Path("prediction_output").mkdir(exist_ok=True)
        df.to_csv("prediction_output/output.csv")
        table_html = df.to_html(classes="table table-striped")
        # print(table_html)
        return templates.TemplateResponse(
            request=request,
            name="table.html",
            context={"table": table_html},
        )

    except Exception as e:
        raise NetworkSecurityException(e, sys)


class URLPredictRequest(BaseModel):
    url: str = Field(..., min_length=1, description="URL a ser analisada")


class ExtractionStatus(BaseModel):
    total_features: int
    calculated_features: int
    fallback_features: int


class URLPredictResponse(BaseModel):
    url: str
    prediction: str
    confidence: float | None
    features: dict[str, int]
    feature_vector: list[int]
    extraction_status: ExtractionStatus
    warnings: list[str]


@app.post("/predict-url")
async def predict_url_route(request: URLPredictRequest) -> URLPredictResponse:
    try:
        extractor = URLFeatureExtractor()
        result = await extractor.extract(request.url)
        features = result["features"]
        warnings = result["warnings"]

        vector = build_feature_vector(features)

        df = pd.DataFrame([features], columns=FEATURE_ORDER)

        preprocessor = load_object("final_model/preprocessor.pkl")
        model_obj = load_object("final_model/model.pkl")
        network_model = NetworkModel(preprocessor=preprocessor, model=model_obj)

        y_pred = network_model.predict(df)
        prediction_label = "legitimate" if int(y_pred[0]) == 1 else "phishing"

        confidence = None
        try:
            proba = network_model.predict_proba(df)
            confidence = float(max(proba[0]))
        except Exception:
            pass

        fallback_warnings = [w for w in warnings if "fallback" in w]
        calculated = 30 - len(fallback_warnings)

        return URLPredictResponse(
            url=request.url,
            prediction=prediction_label,
            confidence=confidence,
            features=features,
            feature_vector=vector,
            extraction_status=ExtractionStatus(
                total_features=30,
                calculated_features=calculated,
                fallback_features=len(fallback_warnings),
            ),
            warnings=fallback_warnings,
        )
    except NetworkSecurityException:
        raise
    except Exception as e:
        raise NetworkSecurityException(e, sys)


if __name__ == "__main__":
    app_run(app, host="0.0.0.0", port=8080)
