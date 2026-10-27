#!/usr/bin/env python3
r"""Encode captioned screen transitions from existing synthetic-report screenshots.

Requires FFmpeg with drawtext and an explicit font file. From the repository root:

    python3 docs/demos/make-investigation-demo.py docs/demos/investigation-demo.json \
        --font /path/to/DejaVuSans.ttf \
        --output docs/assets/screenshots/investigation-walkthrough.gif

Frame paths are relative to the manifest. Each frame supplies a caption and hold
duration in seconds. FFmpeg performs all image processing with one thread; this
script does not capture a browser, run a scan, or contact providers. Identical
inputs, font, and FFmpeg build produce a repeatable animation.
"""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import shutil
import subprocess
import tempfile


def encode(args: argparse.Namespace) -> None:
    manifest = args.manifest.resolve()
    data = json.loads(manifest.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("manifest must be a JSON object")
    frames = data.get("frames", [])
    if not isinstance(frames, list) or not 1 <= len(frames) <= 16:
        raise ValueError("manifest must contain between 1 and 16 frames")
    if not args.font.is_file():
        raise ValueError(f"font file does not exist: {args.font}")
    output = args.output.resolve()
    if output.suffix.lower() != ".gif":
        raise ValueError("output must use the .gif extension")
    if output.exists() and not args.overwrite:
        raise ValueError(f"output already exists; pass --overwrite to replace it: {output}")
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise ValueError("ffmpeg is required on PATH")

    sources = []
    for frame in frames:
        if not isinstance(frame, dict):
            raise ValueError("each frame must be a JSON object")
        source = (manifest.parent / frame["path"]).resolve()
        caption = frame["caption"]
        seconds = frame.get("seconds", 5)
        if not source.is_file() or source.suffix.lower() not in {".png", ".jpg", ".jpeg"}:
            raise ValueError(f"frame must be an existing PNG or JPEG: {source}")
        if not isinstance(caption, str) or not caption.strip() or len(caption) > 80:
            raise ValueError("each caption must contain between 1 and 80 characters")
        if any(char in caption for char in "\r\n\x00"):
            raise ValueError("captions must be a single line")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            raise ValueError("frame duration must be a number")
        if not math.isfinite(seconds) or not 1 <= seconds <= 30:
            raise ValueError("frame duration must be between 1 and 30 seconds")
        sources.append((source, caption, round(seconds * args.fps) / args.fps))

    # Fixed temporary names avoid filter/concat escaping differences across platforms.
    common = [
        ffmpeg, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
        "-threads", "1", "-filter_threads", "1", "-filter_complex_threads", "1",
    ]
    with tempfile.TemporaryDirectory(prefix="kingfisher-demo-") as temporary:
        work = Path(temporary)
        shutil.copyfile(args.font, work / "font.ttf")
        (work / "label.txt").write_text(
            "Synthetic report | Kingfisher HTML triager | Screen transitions", encoding="utf-8"
        )
        header = 80
        concat = ["ffconcat version 1.0"]
        for index, (source, caption, seconds) in enumerate(sources):
            caption_file = f"caption-{index:02}.txt"
            (work / caption_file).write_text(
                f"{index + 1}/{len(sources)}  {caption}", encoding="utf-8"
            )
            frame_file = f"frame-{index:02}.png"
            filters = ",".join([
                f"scale={args.width}:{args.height - header}:force_original_aspect_ratio=decrease:flags=lanczos",
                f"pad={args.width}:{args.height - header}:(ow-iw)/2:(oh-ih)/2:color=0x0b1020",
                f"pad={args.width}:{args.height}:0:{header}:color=0x0b1020",
                "setsar=1",
                "drawtext=fontfile=font.ttf:textfile=label.txt:expansion=none:fontsize=16:fontcolor=0x9bb0ca:x=24:y=12",
                f"drawtext=fontfile=font.ttf:textfile={caption_file}:expansion=none:fontsize=26:fontcolor=white:x=24:y=39",
            ])
            subprocess.run([
                *common, "-i", str(source), "-vf", filters, "-frames:v", "1",
                "-threads", "1", "-update", "1", frame_file,
            ], cwd=work, check=True)
            concat.extend([f"file '{frame_file}'", f"duration {seconds:.6f}"])
        # The repeated final input gives the concat demuxer the final hold duration.
        concat.append(f"file 'frame-{len(sources) - 1:02}.png'")
        (work / "frames.ffconcat").write_text("\n".join(concat) + "\n", encoding="utf-8")
        duration = sum(frame[2] for frame in sources)
        palette = (
            f"fps={args.fps},split[screen][colors];"
            f"[colors]palettegen=max_colors={args.colors}:stats_mode=diff[palette];"
            "[screen][palette]paletteuse=dither=none:diff_mode=rectangle"
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([
            *common, "-f", "concat", "-safe", "1", "-i", "frames.ffconcat",
            "-filter_complex", palette, "-t", f"{duration:.6f}",
            "-threads", "1", "-loop", "0", "-map_metadata", "-1", str(output),
        ], cwd=work, check=True)
    print(
        f"Created {output}: {len(sources)} scenes, {duration:g}s, "
        f"{args.width}x{args.height}, {output.stat().st_size:,} bytes"
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--font", type=Path, required=True, help="Explicit TTF/OTF font for repeatable captions")
    parser.add_argument("--width", type=int, default=1280, choices=range(960, 1921), metavar="960..1920")
    parser.add_argument("--height", type=int, default=800, choices=range(600, 1201), metavar="600..1200")
    parser.add_argument("--fps", type=int, default=1, choices=[1, 2, 5])
    parser.add_argument("--colors", type=int, default=192, choices=[64, 128, 192, 256])
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args()
    try:
        encode(args)
    except (ValueError, KeyError, TypeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"error: {error}\n")


if __name__ == "__main__":
    main()
