from pathlib import Path

import yaml
import pytest

from network_security.utils.main_utils.utils import write_yaml_file


def test_write_yaml_file_writes_content_once(tmp_path: Path):
    """write_yaml_file must write each key exactly once.

    BUG-08: yaml.dump was called twice inside the same open block, causing
    every key in the output file to appear duplicated."""
    output_file = tmp_path / "report.yaml"
    content = {"feature_a": {"p_value": 0.12, "drift_status": False},
               "feature_b": {"p_value": 0.03, "drift_status": True}}

    write_yaml_file(file_path=str(output_file), content=content)

    raw = output_file.read_text()
    parsed = yaml.safe_load(raw)

    assert parsed == content, "Parsed YAML does not match original content"

    for key in content:
        assert raw.count(key) == 1, (
            f"Key '{key}' appears {raw.count(key)} times in the file — "
            "write_yaml_file is likely still calling yaml.dump twice."
        )


def test_write_yaml_file_replace_overwrites_existing(tmp_path: Path):
    """replace=True must delete the existing file and write fresh content."""
    output_file = tmp_path / "report.yaml"
    write_yaml_file(str(output_file), {"old_key": 1})
    write_yaml_file(str(output_file), {"new_key": 2}, replace=True)

    parsed = yaml.safe_load(output_file.read_text())

    assert "new_key" in parsed
    assert "old_key" not in parsed


def test_write_yaml_file_without_replace_overwrites_existing(tmp_path: Path):
    """replace=False (default) still overwrites because open('w') truncates.
    The replace flag only controls whether unlink() is called first — the
    end result is the same: only the latest content survives."""
    output_file = tmp_path / "report.yaml"
    write_yaml_file(str(output_file), {"first": 1})
    write_yaml_file(str(output_file), {"second": 2})

    parsed = yaml.safe_load(output_file.read_text())

    assert "second" in parsed
    assert "first" not in parsed
