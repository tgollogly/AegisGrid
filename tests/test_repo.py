"""Repository consistency checks."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_PATHS = (
    "README.md",
    "WHY.md",
    "QUICKSTART.md",
    "LICENSE",
    "DISCLAIMER.md",
    "core.py",
    "cli.py",
    "assets/aegisgrid-hero-banner.jpg",
    "assets/aegisgrid-hero-banner.svg",
    "assets/README.md",
    "examples/first_run.sh",
)


def test_required_files_exist():
    missing = [p for p in REQUIRED_PATHS if not (ROOT / p).is_file()]
    assert not missing, f"Missing: {missing}"


def test_hero_banner_not_empty():
    hero = ROOT / "assets/aegisgrid-hero-banner.jpg"
    assert hero.stat().st_size > 10_000

def test_readme_embeds_hero():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "assets/aegisgrid-hero-banner.jpg" in readme
    assert "![AegisGrid Hero Banner" in readme
