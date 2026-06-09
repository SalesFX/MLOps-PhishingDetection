import asyncio

import pytest

from network_security.utils.feature_extractor.features import (
    FEATURE_FALLBACKS,
    FEATURE_GROUPS,
    FEATURE_ORDER,
    build_feature_vector,
)
from network_security.utils.feature_extractor.extractor import URLFeatureExtractor


def test_feature_count() -> None:
    assert len(FEATURE_ORDER) == 30


def test_no_duplicate_features() -> None:
    assert len(set(FEATURE_ORDER)) == len(FEATURE_ORDER)


def test_all_features_have_fallback() -> None:
    for feature in FEATURE_ORDER:
        assert feature in FEATURE_FALLBACKS, f"Feature sem fallback: {feature}"


def test_all_features_have_group() -> None:
    for feature in FEATURE_ORDER:
        assert feature in FEATURE_GROUPS, f"Feature sem grupo: {feature}"


def test_build_vector_length() -> None:
    vector = build_feature_vector({})
    assert len(vector) == 30


def test_build_vector_order() -> None:
    overrides = {"URL_Length": 1, "having_IP_Address": -1, "Statistical_report": 1}
    vector = build_feature_vector(overrides)
    assert vector[FEATURE_ORDER.index("having_IP_Address")] == -1
    assert vector[FEATURE_ORDER.index("URL_Length")] == 1
    assert vector[FEATURE_ORDER.index("Statistical_report")] == 1


def test_missing_features_receive_fallback() -> None:
    vector = build_feature_vector({})
    for i, feature in enumerate(FEATURE_ORDER):
        assert vector[i] == FEATURE_FALLBACKS[feature]


def test_extractor_returns_all_features() -> None:
    extractor = URLFeatureExtractor()
    result = asyncio.run(extractor.extract("http://example.com"))
    assert "features" in result
    assert len(result["features"]) == 30
    for feature in FEATURE_ORDER:
        assert feature in result["features"]


def test_extractor_returns_warnings() -> None:
    extractor = URLFeatureExtractor()
    result = asyncio.run(extractor.extract("http://example.com"))
    assert "warnings" in result
    assert len(result["warnings"]) == 30


def test_extractor_build_vector_correct_length() -> None:
    extractor = URLFeatureExtractor()
    result = asyncio.run(extractor.extract("http://example.com"))
    vector = extractor.build_vector(result["features"])
    assert len(vector) == 30
