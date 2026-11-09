#!/usr/bin/env python3
"""Render the README's embeddable-scanner and CLI illustration using Pillow.

Run from any directory with Python 3.10+ and Pillow installed:
    python3 scripts/render-embeddable.py

The PNG is drawn at double resolution before downsampling for crisp typography.
No fonts, external artwork, network access, or generated credentials are bundled.
"""

import os
from functools import lru_cache
from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter, ImageFont, PngImagePlugin

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "docs" / "embeddable.png"
WIDTH, HEIGHT, SCALE = 1600, 1210, 2
WORKFLOW = "Detect Secrets → Validate → Map Blast Radius → Revoke"

# Use native system fonts where available; DejaVu supports Linux regeneration.
WINDOWS_FONTS = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
FONT_CANDIDATES = {
    "regular": [
        (Path("/System/Library/Fonts/Avenir Next.ttc"), 5),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"), 0),
        (WINDOWS_FONTS / "segoeui.ttf", 0),
    ],
    "bold": [
        (Path("/System/Library/Fonts/Avenir Next.ttc"), 0),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"), 0),
        (WINDOWS_FONTS / "segoeuib.ttf", 0),
    ],
    "mono": [
        (Path("/System/Library/Fonts/Menlo.ttc"), 0),
        (Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"), 0),
        (WINDOWS_FONTS / "consola.ttf", 0),
    ],
}

INSTALLS = (
    ("Python", "PyPI · native bindings", "py", "#8EBEFF", "uv add kingfisher-secret-scanner"),
    (
        "Node.js",
        "JavaScript / TypeScript",
        "JS",
        "#F8D979",
        "npm install kingfisher-secret-scanner",
    ),
    (
        "Rust",
        "crates.io · native library",
        "rs",
        "#F6B395",
        "cargo add kingfisher-scanner --features validation",
    ),
)
CLI = (
    "CLI",
    "Standalone scanner",
    ">_",
    "#6EF3BD",
    "uv tool install kingfisher-bin\n"
    "kingfisher scan /path/to/code --view-report",
)


def scaled_box(box):
    return tuple(round(value * SCALE) for value in box)


@lru_cache(maxsize=None)
def font(size, role="regular"):
    for path, index in FONT_CANDIDATES[role]:
        if path.is_file():
            return ImageFont.truetype(str(path), round(size * SCALE), index=index)
    raise FileNotFoundError(
        f"No {role} font found. Install DejaVu fonts or update FONT_CANDIDATES."
    )


def render():
    image = Image.new("RGB", (WIDTH * SCALE, HEIGHT * SCALE), "#051A20")
    glow = Image.new("L", image.size)
    glow_draw = ImageDraw.Draw(glow)
    glow_draw.ellipse(scaled_box((930, -160, 1800, 650)), fill=160)
    glow = glow.filter(ImageFilter.GaussianBlur(190 * SCALE))
    image = Image.composite(Image.new("RGB", image.size, "#0C5747"), image, glow)
    image = image.convert("RGBA")
    draw = ImageDraw.Draw(image)

    def text(x, y, value, size=30, role="regular", fill="#F1F8F7", anchor="lt"):
        draw.text(
            (round(x * SCALE), round(y * SCALE)),
            value,
            font=font(size, role),
            fill=fill,
            anchor=anchor,
        )

    def rounded(box, radius, fill=None, outline=None, width=1):
        draw.rounded_rectangle(
            scaled_box(box),
            radius=round(radius * SCALE),
            fill=fill,
            outline=outline,
            width=round(width * SCALE),
        )

    rounded((18, 18, WIDTH - 18, HEIGHT - 18), 32, outline="#20423F")

    # Restrained orbital lines frame the existing Kingfisher mark, not a new logo.
    for radius in (126, 160, 194):
        draw.ellipse(
            scaled_box((1350 - radius, 256 - radius, 1350 + radius, 256 + radius)),
            outline="#235549",
            width=SCALE,
        )
    for x, y in ((1215, 111), (1538, 208), (1294, 407)):
        draw.ellipse(scaled_box((x - 4, y - 4, x + 4, y + 4)), fill="#53D9AC")

    text(80, 66, "MongoDB", size=34, role="bold")
    wordmark_offset = font(34, "bold").getlength("MongoDB") / SCALE + 13
    text(80 + wordmark_offset, 66, "Kingfisher", size=34, role="bold", fill="#6EF3BD")
    rounded((1160, 62, 1520, 108), 23, fill="#12392F", outline="#346B52")
    text(1340, 85, "APACHE 2.0 · OPEN SOURCE", size=21, fill="#B9F1D0", anchor="mm")

    text(80, 150, "Embeddable", size=88, role="bold")
    text(80, 249, "secret scanner.", size=88, role="bold", fill="#6EF3BD")
    # Draw arrows as vectors: not every system font includes the arrow glyph.
    workflow_steps = WORKFLOW.split(" → ")
    workflow_widths = [font(30).getlength(step) / SCALE for step in workflow_steps]
    assert sum(workflow_widths) + (len(workflow_steps) - 1) * 52 <= 1120, WORKFLOW
    workflow_x = 84
    arrow_y = 358 + font(30).getbbox("Detect Secrets", anchor="lt")[3] / (2 * SCALE)
    for index, (step, step_width) in enumerate(zip(workflow_steps, workflow_widths)):
        text(workflow_x, 358, step, size=30, fill="#BCCFD2")
        workflow_x += step_width
        if index < len(workflow_steps) - 1:
            arrow_start, arrow_end = workflow_x + 14, workflow_x + 38
            draw.line(
                scaled_box((arrow_start, arrow_y, arrow_end, arrow_y)),
                fill="#6EF3BD",
                width=2 * SCALE,
            )
            draw.line(
                [
                    (round((arrow_end - 6) * SCALE), round((arrow_y - 5) * SCALE)),
                    (round(arrow_end * SCALE), round(arrow_y * SCALE)),
                    (round((arrow_end - 6) * SCALE), round((arrow_y + 5) * SCALE)),
                ],
                fill="#6EF3BD",
                width=2 * SCALE,
            )
            workflow_x += 52

    with Image.open(ROOT / "docs" / "kingfisher_logo.png") as source:
        logo = source.convert("RGBA")
    logo = logo.crop(logo.getchannel("A").getbbox())
    logo.thumbnail((230 * SCALE, 290 * SCALE), Image.Resampling.LANCZOS)
    image.alpha_composite(logo, (round(1350 * SCALE - logo.width / 2), 122 * SCALE))

    text(82, 427, "THREE NATIVE SDKS + STANDALONE CLI", size=20, role="bold", fill="#A0B7BA")
    text(
        1518,
        427,
        "SDKs RUN IN-PROCESS · CLI RUNS STANDALONE",
        size=20,
        role="bold",
        fill="#A0B7BA",
        anchor="rt",
    )

    for index, (language, subtitle, badge, accent, command) in enumerate((*INSTALLS, CLI)):
        top, bottom = 466 + index * 154, 604 + index * 154
        rounded((80, top, 1520, bottom), 22, fill="#0C252D", outline="#29464C")
        rounded((81, top + 35, 85, bottom - 35), 2, fill=accent)
        rounded((106, top + 37, 172, top + 103), 16, fill="#19353D")
        text(139, top + 70, badge, size=29, role="mono", fill=accent, anchor="mm")
        text(196, top + 30, language, size=35, role="bold")
        text(196, top + 82, subtitle, size=22, fill="#A4BDC2")

        rounded((504, top + 24, 1492, bottom - 24), 12, fill="#061A21", outline="#1E3D44")
        lines = command.splitlines()
        assert 1 <= len(lines) <= 2, command
        for line_index, line in enumerate(lines):
            center_y = top + 69 + (line_index - (len(lines) - 1) / 2) * 38
            text(528, center_y, "$", size=30, role="mono", fill="#6EF3BD", anchor="lm")
            assert font(30, "mono").getlength(line) / SCALE <= 908, line
            text(566, center_y, line, size=30, role="mono", anchor="lm")

    draw.line(scaled_box((80, 1114, 1520, 1114)), fill="#29464C", width=SCALE)
    text(82, 1144, "Offline detection. Live validation. Explicit revocation.", size=25, fill="#BCCFD2")
    text(1518, 1144, "Same Rust core + rule catalog", size=25, fill="#6EF3BD", anchor="rt")

    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("Title", "Kingfisher: embeddable secret scanner and standalone CLI")
    metadata.add_text(
        "Description",
        "Embed with native Python, Node.js / TypeScript and Rust SDKs, or run the CLI. "
        "One Rust engine and rule catalog. Offline secret detection, live credential "
        "validation, blast-radius mapping and explicit revocation. Apache 2.0 open source.",
    )
    metadata.add_text("Workflow", WORKFLOW)
    for language, _, _, _, command in INSTALLS:
        metadata.add_text(f"Install {language}", command)
    cli_install, cli_scan = CLI[-1].splitlines()
    metadata.add_text("Install CLI", cli_install)
    metadata.add_text("Run CLI", cli_scan)
    image = image.convert("RGB").resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
    image.save(OUTPUT, optimize=True, pnginfo=metadata)
    print(f"Rendered {OUTPUT.relative_to(ROOT)} ({WIDTH} × {HEIGHT}, {OUTPUT.stat().st_size:,} bytes)")


if __name__ == "__main__":
    render()
