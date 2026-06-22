"""Push a Kaggle kernel folder while preserving `machine_shape`.

The Kaggle Python client's public `kernels_push()` path currently reads only
`enable_gpu`; it may ignore the metadata `machine_shape`. This helper mirrors
the small save-kernel request we need and explicitly sends `machine_shape`, so
validation kernels can request `NvidiaTeslaT4`.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


KERNEL_METADATA_FILE = "kernel-metadata.json"


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return data


def notebook_text(path: Path) -> str:
    data = load_json(path)
    for cell in data.get("cells", []):
        if not isinstance(cell, dict):
            continue
        if cell.get("cell_type") == "code":
            cell["outputs"] = []
            cell["execution_count"] = None
        if isinstance(cell.get("source"), list):
            cell["source"] = "".join(str(item) for item in cell["source"])
    return json.dumps(data)


def source_text(path: Path, *, kernel_type: str) -> str:
    if kernel_type == "notebook":
        return notebook_text(path)
    return path.read_text(encoding="utf-8")


def push_kernel(folder: Path) -> dict[str, Any]:
    from kaggle.api.kaggle_api_extended import KaggleApi

    folder = folder.resolve()
    metadata_path = folder / KERNEL_METADATA_FILE
    metadata = load_json(metadata_path)
    code_file = folder / str(metadata.get("code_file") or "")
    if not code_file.is_file():
        raise FileNotFoundError(f"kernel code_file not found: {code_file}")

    api = KaggleApi()
    api.authenticate()

    request_cls = getattr(__import__("kaggle.api.kaggle_api_extended", fromlist=["ApiSaveKernelRequest"]),
                          "ApiSaveKernelRequest")
    request = request_cls()
    request.slug = metadata.get("id")
    request.new_title = metadata.get("title")
    request.text = source_text(code_file, kernel_type=str(metadata.get("kernel_type", "")))
    request.language = metadata.get("language")
    request.kernel_type = metadata.get("kernel_type")
    request.is_private = bool(metadata.get("is_private", True))
    request.enable_gpu = bool(metadata.get("enable_gpu", False))
    request.enable_tpu = bool(metadata.get("enable_tpu", False))
    request.enable_internet = bool(metadata.get("enable_internet", True))
    request.machine_shape = metadata.get("machine_shape")
    request.dataset_data_sources = list(metadata.get("dataset_sources", []))
    request.competition_data_sources = list(metadata.get("competition_sources", []))
    request.kernel_data_sources = list(metadata.get("kernel_sources", []))
    request.model_data_sources = list(metadata.get("model_sources", []))
    request.category_ids = list(metadata.get("keywords", []))

    with api.build_kaggle_client() as client:
        response = client.kernels.kernels_api_client.save_kernel(request)

    return {
        "ok": not bool(getattr(response, "error", None)),
        "error": getattr(response, "error", None),
        "id": metadata.get("id"),
        "title": metadata.get("title"),
        "version_number": getattr(response, "versionNumber", None),
        "url": getattr(response, "url", None),
        "machine_shape": request.machine_shape,
        "enable_gpu": request.enable_gpu,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", type=Path)
    args = parser.parse_args()
    result = push_kernel(args.folder)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
