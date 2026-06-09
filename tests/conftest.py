import os
import sys
from unittest.mock import MagicMock, patch

# dagshub.init() is called at module level in model_trainer.py and makes
# network requests to DagsHub on import. Mock it before any test imports
# the module so tests stay isolated and fast.
sys.modules["dagshub"] = MagicMock()

# data_ingestion.py reads MONGO_DB_URL at module level and raises ValueError
# if it is not set. Provide a fake URL without SRV so the module can be
# imported in tests without a real .env file and without triggering a DNS
# lookup. setdefault leaves real credentials in place when a .env is loaded.
os.environ.setdefault(
    "MONGO_DB_URL",
    "mongodb://fake_user:fake_password@localhost:27017/testdb",
)

# app.py calls MongoClient at module level and then accesses database and
# collection attributes. Patch the class itself so importing `app` never
# touches the network or makes real DNS queries.
_mongo_patcher = patch("pymongo.mongo_client.MongoClient", new_callable=MagicMock)
_mongo_patcher.start()
