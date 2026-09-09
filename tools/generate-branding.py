"""Regenerate the branding raster assets from the 640px source.

Run from the repository root:

    python tools/generate-branding.py

Every output is resampled directly from the source so no frame inherits another
resize's softening. Geometry, colour and the transparent field are preserved;
only the raster size changes.
"""

from pathlib import Path

from PIL import Image

ROOT = Path(__file__).resolve().parent.parent
SOURCES = {
    "light": ROOT / "Logo" / "logo.png",
    "dark": ROOT / "Logo" / "logo dark.png",
}
OUTPUT = ROOT / "Assets"

PNG_SIZES = (32, 48, 256)
ICO_SIZES = (16, 20, 24, 32, 40, 48, 64, 128, 256)
LEGACY_ASSETS = ("logo.png", "logo-32.png", "logo-48.png", "logo-256.png")


def main() -> None:
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name in LEGACY_ASSETS:
        legacy = OUTPUT / name
        if legacy.exists():
            legacy.unlink()

    for theme, source_path in SOURCES.items():
        source = Image.open(source_path).convert("RGBA")
        if source.size != (640, 640):
            raise SystemExit(f"expected a 640x640 source, got {source.size}")
        for size in PNG_SIZES:
            image = source.resize((size, size), Image.LANCZOS)
            image.save(OUTPUT / f"logo-{theme}-{size}.png", "PNG", optimize=True)
            print(f"{theme} png {size:>4} -> {image.size}")

        if theme == "light":
            frames = [source.resize((size, size), Image.LANCZOS) for size in ICO_SIZES]
            frames[-1].save(
                OUTPUT / "app.ico",
                format="ICO",
                sizes=[(size, size) for size in ICO_SIZES],
                append_images=frames[:-1],
            )
            print(f"ico frames -> {list(ICO_SIZES)}")


if __name__ == "__main__":
    main()
