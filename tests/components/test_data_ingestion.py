import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pandas as pd
import pytest

from network_security.exception.exception import NetworkSecurityException


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def ingestion_config(tmp_path: Path):
    config = MagicMock()
    config.feature_store_file_path = str(tmp_path / "feature_store" / "data.csv")
    config.training_file_path      = str(tmp_path / "ingested" / "train.csv")
    config.testing_file_path       = str(tmp_path / "ingested" / "test.csv")
    config.train_test_split_ratio  = 0.2
    config.database_name           = "TEST_DB"
    config.collection_name         = "NetworkData"
    return config


@pytest.fixture
def sample_dataframe():
    rng = np.random.default_rng(42)
    return pd.DataFrame(rng.integers(-1, 2, size=(50, 4)), columns=["a", "b", "c", "d"])


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_export_collection_failure_raises_network_security_exception(ingestion_config):
    """When MongoDB raises an error inside export_collection_as_dataframe(),
    the caller must receive NetworkSecurityException — not TypeError.

    BUG-07: 'raise NetworkSecurityException' without arguments raised
    TypeError('__init__() missing 2 required positional arguments') instead
    of wrapping the original error."""
    from network_security.components.data_ingestion import DataIngestion

    ingestion = DataIngestion(data_ingestion_config=ingestion_config)

    with patch("network_security.components.data_ingestion.pymongo.MongoClient") as mock_client:
        mock_client.side_effect = Exception("simulated MongoDB connection error")

        with pytest.raises(NetworkSecurityException) as exc_info:
            ingestion.export_collection_as_dataframe()

    assert "simulated MongoDB connection error" in str(exc_info.value), (
        "NetworkSecurityException must preserve the original error message."
    )


def test_initiate_data_ingestion_failure_raises_network_security_exception(ingestion_config):
    """When export_collection_as_dataframe() raises inside initiate_data_ingestion(),
    the outer except must re-raise as NetworkSecurityException(e, sys), not TypeError.

    BUG-07: the bare 'raise NetworkSecurityException' on the outer except
    would itself raise TypeError, masking the real error completely."""
    from network_security.components.data_ingestion import DataIngestion

    ingestion = DataIngestion(data_ingestion_config=ingestion_config)

    with patch.object(ingestion, "export_collection_as_dataframe",
                      side_effect=Exception("simulated ingestion failure")):
        with pytest.raises(NetworkSecurityException) as exc_info:
            ingestion.initiate_data_ingestion()

    assert "simulated ingestion failure" in str(exc_info.value)


def test_split_data_writes_train_and_test_files(ingestion_config, sample_dataframe, tmp_path):
    """Happy path: split_data_as_train_test must produce two CSV files."""
    from network_security.components.data_ingestion import DataIngestion

    ingestion = DataIngestion(data_ingestion_config=ingestion_config)
    ingestion.split_data_as_train_test(sample_dataframe)

    assert Path(ingestion_config.training_file_path).exists()
    assert Path(ingestion_config.testing_file_path).exists()

    train_df = pd.read_csv(ingestion_config.training_file_path)
    test_df  = pd.read_csv(ingestion_config.testing_file_path)

    assert len(train_df) + len(test_df) == len(sample_dataframe)
