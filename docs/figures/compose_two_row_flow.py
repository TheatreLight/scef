"""Stack horizontal Mermaid PNGs vertically with connector arrows between them.

Mermaid CLI 11 with the default dagre renderer does not honor `direction LR`
inside nested subgraphs, so wide flowcharts are split into separate LR sources
(parts a, b, c, ...) and recombined here.

Configured groups are listed in GROUPS below; running this script regenerates
all combined PNGs after `mmdc` has rendered the parts.
"""
from __future__ import annotations

from pathlib import Path
from typing import Sequence

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent
PNG = ROOT / "png"

# Each entry: (parts, output)
# parts is a list of (png_filename, internal_row_count) tuples.
# The first part's rendered height is the reference unit. Each subsequent part
# is scaled DOWN to (reference_height * its_row_count) if it would otherwise be
# taller, so font sizes stay roughly proportional between rows.
GROUPS = [
    (
        [
            ("data-flows_02a_container-creation-init.png", 1),
            ("data-flows_02b_container-creation-data.png", 1),
        ],
        "data-flows_02_container-creation-flow.png",
    ),
    (
        [
            ("data-flows_03a_add-file-prepare.png", 1),
            ("data-flows_03b_add-file-write.png", 1),
        ],
        "data-flows_03_add-file-flow.png",
    ),
    (
        [
            ("data-flows_04a_open-container-init.png", 1),
            ("data-flows_04b_open-container-loop.png", 2),
            ("data-flows_04c_open-container-outcome.png", 2),
        ],
        "data-flows_04_open-container-readmeta-flow.png",
    ),
    (
        [
            ("container-format_01a_overview-top.png", 1),
            ("container-format_01b_overview-bottom.png", 1),
        ],
        "container-format_01_overview.png",
    ),
    (
        [
            ("data-flows_05a_extract-select.png", 1),
            ("data-flows_05b_extract-verify.png", 2),
        ],
        "data-flows_05_extract-flow.png",
    ),
    (
        [
            ("data-flows_06a_header-sync-prepare.png", 1),
            ("data-flows_06b_header-sync-write.png", 1),
        ],
        "data-flows_06_header-sync-flow-after-every-write.png",
    ),
]

GAP = 80                # vertical space between rows reserved for the connector
ARROW_HEIGHT = 60       # length of the connector arrow
ARROW_WIDTH = 14        # width of the arrow head
PADDING = 24            # outer white margin
BG = (255, 255, 255)
LINE = (40, 40, 40)


def _scale_to(img: Image.Image, target_h: int) -> Image.Image:
    if target_h >= img.height:
        return img
    scale = target_h / img.height
    return img.resize(
        (max(1, int(round(img.width * scale))), max(1, int(round(img.height * scale)))),
        Image.LANCZOS,
    )


def compose(parts: Sequence[tuple[str, int]], out: Path) -> None:
    if len(parts) < 2:
        raise ValueError(f"need at least 2 parts, got {len(parts)} for {out.name}")

    images: list[Image.Image] = []
    first_path, _ = parts[0]
    first = Image.open(PNG / first_path).convert("RGBA")
    images.append(first)
    reference_row_h = first.height  # one "row" equals the first part's full height

    for path, rows in parts[1:]:
        img = Image.open(PNG / path).convert("RGBA")
        images.append(_scale_to(img, reference_row_h * rows))

    width = max(img.width for img in images) + 2 * PADDING
    height = sum(img.height for img in images) + (len(images) - 1) * GAP + 2 * PADDING

    canvas = Image.new("RGBA", (width, height), BG + (255,))
    draw = ImageDraw.Draw(canvas)

    cx = width // 2
    y = PADDING
    for i, img in enumerate(images):
        x = (width - img.width) // 2
        canvas.paste(img, (x, y), img)
        y_after = y + img.height
        if i < len(images) - 1:
            arrow_top_y = y_after + (GAP - ARROW_HEIGHT) // 2
            arrow_bottom_y = arrow_top_y + ARROW_HEIGHT
            draw.line(
                [(cx, arrow_top_y), (cx, arrow_bottom_y)],
                fill=LINE,
                width=4,
            )
            draw.polygon(
                [
                    (cx, arrow_bottom_y + ARROW_WIDTH),
                    (cx - ARROW_WIDTH, arrow_bottom_y - 2),
                    (cx + ARROW_WIDTH, arrow_bottom_y - 2),
                ],
                fill=LINE,
            )
            y = y_after + GAP
        else:
            y = y_after

    canvas.convert("RGB").save(out, format="PNG")
    print(f"wrote {out}")


def main() -> None:
    for parts, out in GROUPS:
        compose(parts, PNG / out)


if __name__ == "__main__":
    main()
