import os
import sys
from unittest.mock import MagicMock

# dagshub.init() is called at module level in model_trainer.py and makes
# network requests to DagsHub on import. Mock it before any test imports
# the module so tests stay isolated and fast.
sys.modules["dagshub"] = MagicMock()

# data_ingestion.py reads MONGO_DB_URL at module level and raises ValueError
# if it is not set. Provide a fake URL so the module can be imported in
# tests without a real .env file. setdefault leaves real credentials in
# place when a .env is loaded.
os.environ.setdefault(
    "MONGO_DB_URL",
    "mongodb+srv://test_user:test_password@test-cluster.mongodb.net/?retryWrites=true&w=majority",
)
