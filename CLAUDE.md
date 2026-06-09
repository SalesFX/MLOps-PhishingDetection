# CLAUDE.md — Network Security MLOps Project

## 1. Project Context

This is a production-style MLOps project for phishing URL detection.  
It uses MongoDB Atlas, scikit-learn, MLflow/DagsHub, FastAPI, Docker, AWS S3/ECR/EC2, and GitHub Actions.

The project was cloned from an external repository and contains confirmed bugs that must be fixed before any new feature work.  
A full technical audit has been completed and is the source of truth for what needs to change.

**Known confirmed bugs (do not ignore):**
- `evaluation.py` uses `r2_score` to select among classification models — wrong metric
- `model_trainer.py:142` serializes the class `NetworkModel` instead of the instance `network_model`
- `data_validation.py` — `detect_dataset_drift` returns `None` implicitly; validation never fails the pipeline
- `data_ingestion.py:52,106` — `raise NetworkSecurityException` called without arguments
- `utils.py:26` — `yaml.dump` called twice in the same open block
- `config_entity.py:6–7` — bare `print()` calls at module level
- `.github/workflows/main.yaml` — CI steps are `echo` placeholders
- `Dockerfile` — uses Python 3.10 while the project requires 3.12
- `push_data.py:22` — prints the full MongoDB URL with credentials to stdout
- `main.yaml:104` — AWS secrets passed with single quotes, preventing shell expansion

---

## 2. Main Goal

Transform this project into a clean, well-tested, production-style MLOps portfolio.

The evolution must be **incremental and verifiable**. Each change must be:
1. Isolated to one concern
2. Covered by a pytest test
3. Described in a commit message that explains why, not just what

Do not refactor everything at once. Fix one confirmed bug at a time, in priority order.

---

## 3. Working Rules

**Always read before touching.**  
Before modifying any file, read it completely. Do not infer content from filenames or prior context.

**One change per session unless explicitly instructed otherwise.**  
Do not bundle unrelated fixes. A bug fix does not justify surrounding cleanup.

**Confirm the problem before proposing a solution.**  
If the task references a bug, locate the exact line, quote it, and explain the impact before writing any code.

**Never modify files that are not directly related to the current task.**  
Touching `config_entity.py` to fix a bug in `evaluation.py` is not acceptable.

**Do not introduce abstractions not required by the task.**  
No helper functions, base classes, or design patterns unless the task explicitly calls for them.

**Do not add comments that describe what the code does.**  
Only add a comment when the *why* is non-obvious — a constraint, a workaround, or a subtle invariant.

**After every code change, run the relevant test and confirm it passes before reporting completion.**

---

## 4. Python Rules

- **Python version: 3.12 only.** All code, Dockerfiles, and CI environments must use Python 3.12.
- Use `pathlib.Path` for all file system operations. Never use `os.path`.
- All public functions must have type hints on parameters and return values.
- Do not use bare `except:` clauses. Always catch specific exception types or re-raise with `raise NetworkSecurityException(e, sys)`.
- `raise NetworkSecurityException` must always receive two arguments: `(e, sys)`. Calling it bare is a bug.
- Do not leave `print()` statements in library or pipeline code. Use `logging`.
- Module-level side effects (prints, network calls, file I/O) are forbidden in importable modules.
- `requirements.txt` must have pinned versions for all dependencies. Unpinned dependencies are a reproducibility risk.

---

## 5. MLOps Rules

### This is a binary classification problem. Not regression.

The target column `Result` contains values `{-1, 1}`, remapped to `{0, 1}` during transformation.  
**R² Score is a regression metric. It must never be used here.**

**Metrics allowed for model selection and evaluation:**
- F1 Score (primary selection metric)
- Precision
- Recall
- ROC AUC (add if feasible)

**Forbidden:**
- `r2_score` from `sklearn.metrics` — must not appear anywhere in this codebase
- Selecting models by any regression metric

**Model serialization:**
- The trained model must always be saved as an *instance*, not a class reference.
- `save_object(..., obj=network_model)` — the variable holding the fitted object, not `NetworkModel` the class.

**Data validation must be a hard gate:**
- If column count is wrong, raise an exception and stop the pipeline.
- If required numerical columns are missing or wrong type, raise an exception and stop the pipeline.
- `detect_dataset_drift` must return a `bool`. A `None` return is a bug.

**Preprocessing:**
- The current KNNImputer-only pipeline is acceptable for now.
- Do not add feature engineering or normalization unless explicitly tasked.

**MLflow:**
- Metrics logged must match the selection metric (F1-based).
- `mlflow.sklearn.log_model` (currently commented out) should be enabled when the model serialization bug is fixed.

**Artifact paths:**
- Preprocessor must be saved in exactly one location per pipeline run: the timestamped artifact directory.
- `final_model/preprocessor.pkl` is the stable serve path. It must be written by one component only.

---

## 6. Security Rules

**No secrets or credentials in source code.** Ever.

- MongoDB connection strings must be fully constructed from environment variables.  
  The cluster hostname `cluster0.l5ee6dv.mongodb.net` must move to an environment variable (`MONGO_DB_HOST` or `MONGO_DB_URL`).
- Credentials must never be printed, logged, or included in exception messages.
- `push_data.py` must not print the constructed URL.
- AWS credentials must not appear in docker run commands as literals.
- All secrets in GitHub Actions must use `${{ secrets.NAME }}` inside double-quoted strings.

**`.env` is already in `.gitignore` — keep it there. Do not commit it.**

**`.dockerignore` must exist** and must exclude: `.env`, `*.pkl`, `Artifacts/`, `mlruns/`, `logs/`, `.git/`.

**API security baseline:**
- The `/train` endpoint must not be reachable without authentication in a production deployment.
- `allow_origins=["*"]` is acceptable for local development only. Document this clearly.

---

## 7. API Rules

- FastAPI is the web framework. Do not replace it.
- Endpoints: `GET /` (redirect to docs), `GET /train`, `POST /predict`.
- The `/predict` endpoint must validate that the uploaded CSV contains the expected columns before running inference.
- If `final_model/model.pkl` or `final_model/preprocessor.pkl` do not exist, `/predict` must return a clear HTTP 503 error, not a 500 traceback.
- Do not add new endpoints unless explicitly tasked.
- Type hints on all route parameters and return types.
- Do not expose internal exception details to API consumers.

---

## 8. Docker Rules

- Base image: `python:3.12-slim`. The `buster` variant is end-of-life.
- The Dockerfile must use a non-root user for running the application.
- A `HEALTHCHECK` instruction must be present, targeting the `/docs` or a `/health` endpoint.
- A `.dockerignore` file must exist before the Dockerfile is considered correct.
- `apt-get update` must be called once. Do not call both `apt update` and `apt-get update` in the same RUN block.
- AWS CLI installation in the image is acceptable only if S3 sync is used at runtime. If sync moves to boto3, remove it.
- Multi-stage builds are preferred for production images but not required for the initial fix phase.
- Do not `COPY . /app` without a `.dockerignore` in place.

---

## 9. CI/CD Rules

**The CI/CD pipeline must be real. No placeholder steps.**

`echo "Running unit tests"` is not a test. It must be replaced with:

```yaml
- name: Run unit tests
  run: |
    pip install -r requirements.txt
    pytest tests/ -v --tb=short
```

**Job structure (must be maintained):**
1. `integration` — lint + pytest. Must fail on real errors.
2. `build-and-push-ecr-image` — build Docker image, push to ECR. Runs only if `integration` passes.
3. `Continuous-Deployment` — pull from ECR, stop existing container, run new container. Runs only if delivery passes.

**Docker run in deployment job:**
- Use double quotes around `-e` values: `-e "VAR=${{ secrets.VAR }}"`.
- The `docker stop` step must not be commented out. Existing containers must be stopped before new ones start.
- `docker system prune -f` is acceptable for disk cleanup.

**GitHub Actions action versions:**
- `actions/checkout@v3` is the minimum. Prefer `@v4` when updating.
- `aws-actions/configure-aws-credentials@v1` should be updated to `@v4` when touching the workflow.
- `::set-output` is deprecated — replace with `$GITHUB_OUTPUT`.

**Branch protection:**
- CI must pass before merge to `main`.
- Do not bypass CI with `--no-verify` or workflow conditions that skip tests.

---

## 10. Documentation Rules

- `README.md` must accurately reflect the current state of the project.  
  If a bug is fixed, update the relevant section. Do not leave known-broken instructions.
- Every bug fix must be accompanied by a commit message explaining *why the original code was wrong*, not just what changed.
- Do not create additional markdown files (design docs, changelogs, ADRs) unless explicitly requested.
- Do not add docstrings to every function. Only document functions where the *why* or the *contract* is non-obvious.
- The `data_schema/schema.yaml` is the authoritative definition of the dataset schema. If columns change, update it first, then update validation code.
- `CLAUDE.md` (this file) is the source of truth for how to work on this project.  
  If a rule proves wrong or impractical, propose updating it here rather than silently ignoring it.
