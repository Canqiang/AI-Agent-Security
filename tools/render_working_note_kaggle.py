#!/usr/bin/env python3
"""Render the repository Working Note with Kaggle-hosted image URLs."""

from __future__ import annotations

import argparse
from pathlib import Path


KAGGLE_IMAGE_URLS = {
    "assets/working-note/01-scoring-pipeline.png": (
        "https://www.googleapis.com/download/storage/v1/b/kaggle-user-content/o/"
        "inbox%2F3072872%2Fa4e5184bba90ad6ce55681dd2360c7ea%2F"
        "01-scoring-pipeline.png?generation=1784618186603607&alt=media"
    ),
    "assets/working-note/02-attack-surface-collapse.png": (
        "https://www.googleapis.com/download/storage/v1/b/kaggle-user-content/o/"
        "inbox%2F3072872%2F11e45a374f299a5c76956339359dc95c%2F"
        "02-attack-surface-collapse.png?generation=1784618299422803&alt=media"
    ),
    "assets/working-note/03-window-nesting-proof.png": (
        "https://www.googleapis.com/download/storage/v1/b/kaggle-user-content/o/"
        "inbox%2F3072872%2F4bf40505d90d6bafecdeb802742ab4a2%2F"
        "03-window-nesting-proof.png?generation=1784618345271188&alt=media"
    ),
    "assets/working-note/04-score-economics.png": (
        "https://www.googleapis.com/download/storage/v1/b/kaggle-user-content/o/"
        "inbox%2F3072872%2Fbfcba3d355e406fe88a1936402ba83a2%2F"
        "04-score-economics.png?generation=1784618386850249&alt=media"
    ),
}


def render_markdown(markdown: str) -> str:
    for local_path, kaggle_url in KAGGLE_IMAGE_URLS.items():
        count = markdown.count(local_path)
        if count != 1:
            raise ValueError(
                f"expected Working Note image {local_path} exactly once; appears {count} times"
            )
        markdown = markdown.replace(local_path, kaggle_url)
    return markdown


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    rendered = render_markdown(args.source.read_text())
    args.output.write_text(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
