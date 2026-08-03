from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "render_working_note_kaggle.py"


def test_renderer_replaces_all_local_working_note_images(tmp_path: Path) -> None:
    source = tmp_path / "note.md"
    output = tmp_path / "note.kaggle.md"
    source.write_text(
        "\n".join(
            [
                "# Note",
                "![pipeline](assets/working-note/01-scoring-pipeline.png)",
                "![surface](assets/working-note/02-attack-surface-collapse.png)",
                "![proof](assets/working-note/03-window-nesting-proof.png)",
                "![economics](assets/working-note/04-score-economics.png)",
                "![decomposition](assets/working-note/05-wrapup-cost-decomposition.png)",
                "",
            ]
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    rendered = output.read_text()
    # every local working-note image path must be gone, replaced by a hosted URL
    assert "assets/working-note/" not in rendered
    # all five mapped images render as Kaggle-hosted URLs (the hosted filename need
    # not match the local one — figure 5's hosted object is named fig5-*.png)
    hosted_prefix = "https://www.googleapis.com/download/storage/v1/b/kaggle-user-content/o/"
    assert rendered.count(hosted_prefix) == 5


def test_renderer_fails_if_expected_image_is_missing(tmp_path: Path) -> None:
    source = tmp_path / "note.md"
    output = tmp_path / "note.kaggle.md"
    source.write_text(
        "\n".join(
            [
                "![pipeline](assets/working-note/01-scoring-pipeline.png)",
                "![surface](assets/working-note/02-attack-surface-collapse.png)",
                "![proof](assets/working-note/03-window-nesting-proof.png)",
                "",
            ]
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "04-score-economics.png" in result.stderr
    assert not output.exists()


def test_renderer_fails_if_expected_image_is_duplicated(tmp_path: Path) -> None:
    source = tmp_path / "note.md"
    output = tmp_path / "note.kaggle.md"
    source.write_text(
        "\n".join(
            [
                "![pipeline](assets/working-note/01-scoring-pipeline.png)",
                "![pipeline again](assets/working-note/01-scoring-pipeline.png)",
                "![surface](assets/working-note/02-attack-surface-collapse.png)",
                "![proof](assets/working-note/03-window-nesting-proof.png)",
                "![economics](assets/working-note/04-score-economics.png)",
                "",
            ]
        )
    )

    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "--source",
            str(source),
            "--output",
            str(output),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    assert "01-scoring-pipeline.png" in result.stderr
    assert "2 times" in result.stderr
    assert not output.exists()
