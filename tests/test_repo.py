"""Repository consistency checks."""

import xml.etree.ElementTree as ET
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
    "assets/aegisgrid-architecture.svg",
    "assets/aegisgrid-architecture.png",
    "assets/README.md",
    "examples/first_run.sh",
)


def test_required_files_exist():
    missing = [p for p in REQUIRED_PATHS if not (ROOT / p).is_file()]
    assert not missing, f"Missing: {missing}"


def test_hero_banner_not_empty():
    hero = ROOT / "assets/aegisgrid-hero-banner.jpg"
    assert hero.stat().st_size > 10_000


def test_no_linkedin_marketing_file_in_repo():
    assert not (ROOT / "LINKEDIN.md").exists()


def test_readme_embeds_hero():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "assets/aegisgrid-hero-banner.jpg" in readme
    assert "![AegisGrid Hero Banner" in readme


def test_readme_embeds_architecture_diagram():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "assets/aegisgrid-architecture.png" in readme
    png = ROOT / "assets/aegisgrid-architecture.png"
    assert png.is_file() and png.stat().st_size > 5000


def test_architecture_svg_is_valid_xml():
    svg_path = ROOT / "assets/aegisgrid-architecture.svg"
    ET.parse(svg_path)
