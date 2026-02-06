from __future__ import annotations

import re
import textwrap
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


PAGE_WIDTH = 8.27  # A4 width in inches
PAGE_HEIGHT = 11.69  # A4 height in inches
LEFT_MARGIN = 0.7
RIGHT_MARGIN = 0.7
TOP_MARGIN = 0.7
BOTTOM_MARGIN = 0.7

FONT_BODY = "DejaVu Sans"
FONT_MONO = "DejaVu Sans Mono"


def _wrap_text(text: str, font_size: int) -> list[str]:
    width_in = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN
    char_width = (font_size * 0.55) / 72
    max_chars = max(30, int(width_in / char_width))
    return textwrap.wrap(text, max_chars)


def _escape_text(text: str) -> str:
    return text.replace("$", "\\$")


def _parse_blocks(lines: list[str]) -> list[tuple]:
    blocks: list[tuple] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip("\n")

        if line.startswith("```"):
            lang = line[3:].strip()
            i += 1
            code_lines: list[str] = []
            while i < len(lines) and not lines[i].startswith("```"):
                code_lines.append(lines[i].rstrip("\n"))
                i += 1
            blocks.append(("code", "\n".join(code_lines), lang))
            if i < len(lines):
                i += 1
            continue

        if line.startswith("#"):
            level = len(line) - len(line.lstrip("#"))
            text = line[level:].strip()
            blocks.append(("heading", level, text))
            i += 1
            continue

        if line.strip() == "":
            blocks.append(("spacer",))
            i += 1
            continue

        image_match = re.match(r"!\[(.*?)\]\((.*?)\)", line.strip())
        if image_match:
            blocks.append(("image", image_match.group(2), image_match.group(1)))
            i += 1
            continue

        if line.lstrip().startswith("- "):
            items: list[str] = []
            while i < len(lines) and lines[i].lstrip().startswith("- "):
                items.append(lines[i].lstrip()[2:].rstrip("\n"))
                i += 1
            blocks.append(("list", items))
            continue

        para = [line.strip()]
        i += 1
        while i < len(lines):
            next_line = lines[i].rstrip("\n")
            if (
                next_line.strip() == ""
                or next_line.startswith("#")
                or next_line.startswith("```")
                or next_line.lstrip().startswith("- ")
                or next_line.lstrip().startswith("![")
            ):
                break
            para.append(next_line.strip())
            i += 1
        blocks.append(("paragraph", " ".join(para)))

    return blocks


class PdfRenderer:
    def __init__(self, pdf_path: Path):
        self.pdf = PdfPages(pdf_path)
        self.fig = None
        self.ax = None
        self.y = TOP_MARGIN
        self._new_page()

    def _new_page(self) -> None:
        if self.fig is not None:
            self.pdf.savefig(self.fig)
            plt.close(self.fig)
        self.fig = plt.figure(figsize=(PAGE_WIDTH, PAGE_HEIGHT))
        self.ax = self.fig.add_axes([0, 0, 1, 1])
        self.ax.set_xlim(0, PAGE_WIDTH)
        self.ax.set_ylim(0, PAGE_HEIGHT)
        self.ax.invert_yaxis()
        self.ax.axis("off")
        self.y = TOP_MARGIN

    def _ensure_space(self, height: float) -> None:
        if self.y + height > PAGE_HEIGHT - BOTTOM_MARGIN:
            self._new_page()

    def add_heading(self, text: str, level: int) -> None:
        sizes = {1: 16, 2: 14, 3: 12}
        font_size = sizes.get(level, 11)
        lines = _wrap_text(_escape_text(text), font_size)
        height = len(lines) * (font_size * 1.3 / 72) + 0.1
        self._ensure_space(height)
        for line in lines:
            self.ax.text(
                LEFT_MARGIN,
                self.y,
                line,
                fontsize=font_size,
                fontfamily=FONT_BODY,
                fontweight="bold",
                va="top",
            )
            self.y += font_size * 1.3 / 72
        self.y += 0.08

    def add_paragraph(self, text: str, font_size: int = 10) -> None:
        lines = _wrap_text(_escape_text(text), font_size)
        height = len(lines) * (font_size * 1.2 / 72) + 0.08
        self._ensure_space(height)
        for line in lines:
            self.ax.text(
                LEFT_MARGIN,
                self.y,
                line,
                fontsize=font_size,
                fontfamily=FONT_BODY,
                va="top",
            )
            self.y += font_size * 1.2 / 72
        self.y += 0.06

    def add_list(self, items: list[str], font_size: int = 10) -> None:
        for item in items:
            lines = _wrap_text(_escape_text(item), font_size)
            height = len(lines) * (font_size * 1.2 / 72) + 0.02
            self._ensure_space(height)
            for idx, line in enumerate(lines):
                prefix = "- " if idx == 0 else "  "
                self.ax.text(
                    LEFT_MARGIN,
                    self.y,
                    prefix + line,
                    fontsize=font_size,
                    fontfamily=FONT_BODY,
                    va="top",
                )
                self.y += font_size * 1.2 / 72
            self.y += 0.02
        self.y += 0.04

    def add_code(self, text: str, font_size: int = 8) -> None:
        lines = text.splitlines() if text else [""]
        wrapped_lines: list[str] = []
        for line in lines:
            wrapped_lines.extend(_wrap_text(_escape_text(line), font_size))
        height = len(wrapped_lines) * (font_size * 1.25 / 72) + 0.1
        self._ensure_space(height)
        for line in wrapped_lines:
            self.ax.text(
                LEFT_MARGIN,
                self.y,
                line,
                fontsize=font_size,
                fontfamily=FONT_MONO,
                va="top",
            )
            self.y += font_size * 1.25 / 72
        self.y += 0.06

    def add_image(self, image_path: Path) -> None:
        if not image_path.exists():
            self.add_paragraph(f"[Missing image: {image_path}]", font_size=9)
            return
        img = plt.imread(image_path)
        img_height, img_width = img.shape[:2]
        aspect = img_width / img_height

        max_width = PAGE_WIDTH - LEFT_MARGIN - RIGHT_MARGIN
        width = max_width
        height = width / aspect
        max_height = 3.6
        if height > max_height:
            height = max_height
            width = height * aspect

        self._ensure_space(height + 0.2)
        x0 = LEFT_MARGIN
        x1 = x0 + width
        y0 = self.y
        y1 = y0 + height
        self.ax.imshow(img, extent=(x0, x1, y0, y1))
        self.y += height + 0.12

    def add_spacer(self, size: float = 0.08) -> None:
        self._ensure_space(size)
        self.y += size

    def close(self) -> None:
        if self.fig is not None:
            self.pdf.savefig(self.fig)
            plt.close(self.fig)
        self.pdf.close()


def render_markdown_to_pdf(md_path: Path, pdf_path: Path) -> None:
    lines = md_path.read_text().splitlines()
    blocks = _parse_blocks(lines)
    renderer = PdfRenderer(pdf_path)

    for block in blocks:
        kind = block[0]
        if kind == "heading":
            renderer.add_heading(block[2], block[1])
        elif kind == "paragraph":
            renderer.add_paragraph(block[1])
        elif kind == "list":
            renderer.add_list(block[1])
        elif kind == "code":
            code_text = block[1]
            lang = block[2]
            if lang == "mermaid":
                if "sequenceDiagram" in code_text:
                    renderer.add_image(md_path.parent / "assets" / "sequence_diagram.png")
                elif "flowchart" in code_text:
                    renderer.add_image(md_path.parent / "assets" / "architecture_diagram.png")
                else:
                    renderer.add_code(code_text)
            else:
                renderer.add_code(code_text)
        elif kind == "image":
            image_path = (md_path.parent / block[1]).resolve()
            renderer.add_image(image_path)
        elif kind == "spacer":
            renderer.add_spacer()

    renderer.close()


def main() -> None:
    docs_dir = Path(__file__).resolve().parent
    ru_md = docs_dir / "PII_Masking_Service_Design_ru.md"
    en_md = docs_dir / "PII_Masking_Service_Design_en.md"
    render_markdown_to_pdf(ru_md, docs_dir / "PII_Masking_Service_Design_ru.pdf")
    render_markdown_to_pdf(en_md, docs_dir / "PII_Masking_Service_Design_en.pdf")


if __name__ == "__main__":
    main()
