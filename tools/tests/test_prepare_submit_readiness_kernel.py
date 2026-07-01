from __future__ import annotations
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO / "tools"))

import prepare_submit_readiness_kernel as psrk  # noqa: E402


def test_build_kernel_writes_notebook_and_metadata(tmp_path):
    result = psrk.build_kernel(tmp_path, kernel_id="canqiang/aiagsec-submit-readiness", title="Test Title")
    assert result["ok"] is True
    assert result["embedded_files"] == list(psrk.EMBEDDED_FILES)

    notebook_path = Path(result["notebook"])
    metadata_path = Path(result["metadata"])
    assert notebook_path.exists() and notebook_path.name == "submit_readiness.ipynb"
    assert metadata_path.exists()

    metadata = json.loads(metadata_path.read_text())
    assert metadata["id"] == "canqiang/aiagsec-submit-readiness"
    assert metadata["title"] == "Test Title"
    assert metadata["code_file"] == "submit_readiness.ipynb"
    assert metadata["machine_shape"] == "NvidiaTeslaT4"

    notebook = json.loads(notebook_path.read_text())
    cell_types = [c["cell_type"] for c in notebook["cells"]]
    assert cell_types.count("code") >= 2  # at least the bootstrap cell + original code cells
    bootstrap_source = "".join(notebook["cells"][2]["source"])
    assert "bootstrapped submit-readiness files" in bootstrap_source
