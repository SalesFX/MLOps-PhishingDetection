# MLOps Phishing Detection

A production-style MLOps platform for phishing URL detection. Accepts a raw URL or a pre-extracted feature CSV, runs the full inference pipeline, and returns whether the URL is phishing or legitimate — with confidence score, feature breakdown and warnings.

![CI/CD](https://github.com/SalesFX/MLOps-PhishingDetection/actions/workflows/main.yaml/badge.svg)

---

## Architecture

![Architecture](images/architecture.png)

**Stack:** MongoDB Atlas · scikit-learn · MLflow · FastAPI · Docker · AWS S3 / ECR / EC2 · GitHub Actions · Terraform

---

## Interface

| Home | Phishing Result + History |
|------|--------------------------|
| ![Home](images/screenshot-url-checker.png) | ![Phishing](images/screenshot-result-phishing-and-history.png) |

| Legitimate Result | CI/CD Pipeline |
|-------------------|----------------|
| ![Legitima](images/screenshot-result-legitimate.png) | ![CICD](images/screenshot-cicd-pipeline.png) |

---

## Prediction Modes

### URL Mode — `POST /predict-url`

The user submits a raw URL. The system automatically:

1. Validates the URL against SSRF rules
2. Extracts 30 numerical features across 4 groups (string, HTTP/HTML, DNS/WHOIS, external APIs)
3. Builds the ordered feature vector
4. Runs the trained Gradient Boosting model
5. Returns prediction, confidence, all 30 features and any warnings

```bash
curl -X POST http://localhost:8080/predict-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com/login"}'
```

```json
{
  "url": "https://example.com/login",
  "prediction": "legitimate",
  "confidence": 0.97,
  "features": { "having_IP_Address": 1, "SSLfinal_State": 1 },
  "feature_vector": [1, 1, 1, 1, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0],
  "extraction_status": { "total_features": 30, "calculated_features": 27, "fallback_features": 3 },
  "warnings": ["Page_Rank: fallback documentado ..."]
}
```

### CSV Mode — `POST /predict`

Accepts a CSV file with the 30 pre-extracted features. Returns an HTML table with the `predicted_column` appended. Designed for batch processing, dataset reprocessing and technical experiments.

```bash
curl -X POST http://localhost:8080/predict \
  -F "file=@data/samples/predict_sample.csv"
```

> Full contracts: [docs/api.md](docs/api.md)

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/SalesFX/MLOps-PhishingDetection.git
cd MLOps-PhishingDetection
pip install -e ".[dev]"

# 2. Configure environment
echo "MONGO_DB_URL=your_connection_string" > .env

# 3. Run
python app.py

# 4. Open
# http://localhost:8080/url-checker
```

> The model must be trained before predictions. Use the **Treinar Modelo** button on the interface or `GET /train`.

---

## API Routes

| Route | Method | Description |
|-------|--------|-------------|
| `/url-checker` | GET | Web interface |
| `/predict-url` | POST | Predict from raw URL |
| `/predict` | POST | Predict from feature CSV |
| `/train` | GET | Run training pipeline |
| `/docs` | GET | OpenAPI / Swagger UI |

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `MONGO_DB_URL` | Yes | MongoDB Atlas connection string |
| `GOOGLE_SAFE_BROWSING_API_KEY` | No | Enables `Statistical_report` via Google Safe Browsing API |

Without `GOOGLE_SAFE_BROWSING_API_KEY` the system runs normally — `Statistical_report` falls back to `0` with a warning.

---

## Tests

```bash
uv run pytest tests/ -v
```

151 tests — all dependencies mocked, no real network calls required.

---

## Documentation

| Doc | Contents |
|-----|----------|
| [docs/api.md](docs/api.md) | Full API contracts and request/response schemas |
| [docs/feature-extraction.md](docs/feature-extraction.md) | All 30 features, groups, semantics and fallback strategy |
| [docs/security.md](docs/security.md) | SSRF protection rules and implementation |
| [docs/infra-spec.md](docs/infra-spec.md) | Terraform infrastructure specification |

---

## Known Limitations

- **Tranco rank** measures popularity, not security — used as a weak auxiliary signal for `web_traffic`
- **Google Safe Browsing** requires an API key; `Statistical_report` falls back to `0` without it
- **PageRank** (original) is obsolete since 2016; Open PageRank measures SEO authority, not phishing risk
- **Google Index** has no free official API; scraping is not used
- **Backlinks** (`Links_pointing_to_page`) require paid APIs; correlation with phishing is only +0.03 in the dataset
- Model output is probabilistic — intended as a decision-support signal, not an absolute verdict
