from __future__ import annotations

import base64
import os
import random
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

if "PII_KEY_B64" not in os.environ:
    os.environ["PII_KEY_B64"] = base64.b64encode(b"\x00" * 64).decode("ascii")

from app.config import settings


ASSETS_DIR = Path(__file__).resolve().parent / "assets"
ASSETS_DIR.mkdir(parents=True, exist_ok=True)

COLORS = {
    "text": "#1F2937",
    "line": "#374151",
    "on_prem_fill": "#E8F3FF",
    "cloud_fill": "#FFF4D6",
    "decision_fill": "#E9F8EF",
    "llm_fill": "#E6F7FF",
    "rm_fill": "#F3F4F6",
    "client_fill": "#F5F5F5",
    "on_prem_line": "#2563EB",
    "cloud_line": "#D97706",
    "decision_line": "#16A34A",
    "llm_line": "#0EA5E9",
    "rm_line": "#64748B",
}


def _save_fig(name: str) -> None:
    path = ASSETS_DIR / name
    plt.tight_layout()
    plt.savefig(path, dpi=160)
    plt.close()


def plot_diagonal_scaling() -> None:
    scale = settings.scale_factors.get("amount", 1.37)
    x = list(range(0, 101, 5))
    y = x
    y_scaled = [v * scale for v in x]

    plt.figure(figsize=(6, 4))
    plt.plot(x, y, label="y = x", linewidth=2)
    plt.plot(x, y_scaled, label=f"y = {scale:.2f}x", linewidth=2)
    plt.title("Diagonal Scaling for Numeric Fields")
    plt.xlabel("Original value (x)")
    plt.ylabel("Masked value (x')")
    plt.legend(loc="upper left")
    plt.grid(True, alpha=0.3)
    _save_fig("diagonal_scaling.png")


def plot_mcc_permutation_scatter() -> None:
    rng = random.Random(settings.cat_seed)
    perm = list(range(10000))
    rng.shuffle(perm)

    sample = list(range(0, 10000, 40))
    x_vals = sample
    y_vals = [perm[idx] for idx in sample]

    plt.figure(figsize=(6, 4))
    plt.scatter(x_vals, y_vals, s=12, alpha=0.7)
    plt.title("MCC Permutation (sample)")
    plt.xlabel("Original MCC")
    plt.ylabel("Masked MCC")
    plt.grid(True, alpha=0.3)
    _save_fig("mcc_permutation_scatter.png")


def plot_aead_determinism() -> None:
    fig, ax = plt.subplots(figsize=(7, 3.5))
    ax.axis("off")

    ax.add_patch(Rectangle((0.05, 0.6), 0.35, 0.25, fill=False, linewidth=1.5))
    ax.text(0.07, 0.74, "Plaintext: John Smith\nAD: full_name", fontsize=9)

    ax.add_patch(Rectangle((0.6, 0.6), 0.35, 0.25, fill=False, linewidth=1.5))
    ax.text(0.62, 0.74, "Ciphertext C1\n(deterministic)", fontsize=9)

    ax.add_patch(Rectangle((0.05, 0.15), 0.35, 0.25, fill=False, linewidth=1.5))
    ax.text(0.07, 0.29, "Plaintext: John Smith\nAD: email", fontsize=9)

    ax.add_patch(Rectangle((0.6, 0.15), 0.35, 0.25, fill=False, linewidth=1.5))
    ax.text(0.62, 0.29, "Ciphertext C2\n(different AD)", fontsize=9)

    ax.annotate("", xy=(0.6, 0.72), xytext=(0.4, 0.72), arrowprops=dict(arrowstyle="->"))
    ax.annotate("", xy=(0.6, 0.27), xytext=(0.4, 0.27), arrowprops=dict(arrowstyle="->"))

    ax.text(0.05, 0.02, "Same plaintext + same AD => same ciphertext (deterministic)", fontsize=8)
    ax.text(0.05, 0.0, "Same plaintext + different AD => different ciphertext", fontsize=8)

    plt.title("AES-256-SIV Determinism and Domain Separation", fontsize=10)
    _save_fig("aead_determinism.png")


def plot_llm_masked_exchange() -> None:
    fig, ax = plt.subplots(figsize=(7, 3))
    ax.axis("off")

    ax.add_patch(Rectangle((0.05, 0.55), 0.25, 0.3, fill=False, linewidth=1.5))
    ax.text(0.07, 0.7, "On-Prem\nmask_text()", fontsize=9)

    ax.add_patch(Rectangle((0.375, 0.55), 0.25, 0.3, fill=False, linewidth=1.5))
    ax.text(0.39, 0.7, "LLM\n(masked only)", fontsize=9)

    ax.add_patch(Rectangle((0.7, 0.55), 0.25, 0.3, fill=False, linewidth=1.5))
    ax.text(0.72, 0.7, "On-Prem\nunmask_text()", fontsize=9)

    ax.annotate("", xy=(0.375, 0.7), xytext=(0.3, 0.7), arrowprops=dict(arrowstyle="->"))
    ax.annotate("", xy=(0.7, 0.7), xytext=(0.625, 0.7), arrowprops=dict(arrowstyle="->"))

    ax.text(0.05, 0.2, "Tokens: [[ENC|v1|field|ciphertext]]", fontsize=8)
    ax.text(0.05, 0.1, "No plaintext leaves on-prem", fontsize=8)

    plt.title("LLM Masked Exchange", fontsize=10)
    _save_fig("llm_masked_exchange.png")

def plot_architecture_diagram() -> None:
    fig, ax = plt.subplots(figsize=(8, 3.6))
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    boxes = {
        "Client": (0.02, 0.62, 0.16, 0.22),
        "Service": (0.24, 0.62, 0.22, 0.22),
        "Cloud": (0.52, 0.62, 0.2, 0.22),
        "Decision": (0.76, 0.62, 0.22, 0.22),
        "LLM": (0.52, 0.18, 0.2, 0.22),
        "RM": (0.76, 0.18, 0.22, 0.22),
    }

    def draw_box(label: str, x: float, y: float, w: float, h: float) -> None:
        ax.add_patch(Rectangle((x, y), w, h, facecolor="white", edgecolor=COLORS["line"], linewidth=1.4))
        ax.text(x + w / 2, y + h / 2, label, ha="center", va="center", fontsize=10, color=COLORS["text"])

    ax.add_patch(Rectangle((0.01, 0.56), 0.98, 0.34, facecolor=COLORS["on_prem_fill"], alpha=0.35, edgecolor="none"))
    ax.add_patch(Rectangle((0.5, 0.12), 0.24, 0.34, facecolor=COLORS["cloud_fill"], alpha=0.4, edgecolor="none"))
    ax.add_patch(Rectangle((0.74, 0.12), 0.25, 0.34, facecolor=COLORS["rm_fill"], alpha=0.4, edgecolor="none"))

    draw_box("Client\nSource System", *boxes["Client"])
    ax.add_patch(Rectangle((boxes["Service"][0], boxes["Service"][1]), boxes["Service"][2], boxes["Service"][3],
                           facecolor=COLORS["on_prem_fill"], edgecolor=COLORS["line"], linewidth=1.4))
    ax.text(boxes["Service"][0] + boxes["Service"][2] / 2, boxes["Service"][1] + boxes["Service"][3] / 2,
            "PII Masking\nService (On-Prem)", ha="center", va="center", fontsize=10, color=COLORS["text"])

    ax.add_patch(Rectangle((boxes["Cloud"][0], boxes["Cloud"][1]), boxes["Cloud"][2], boxes["Cloud"][3],
                           facecolor=COLORS["cloud_fill"], edgecolor=COLORS["line"], linewidth=1.4))
    ax.text(boxes["Cloud"][0] + boxes["Cloud"][2] / 2, boxes["Cloud"][1] + boxes["Cloud"][3] / 2,
            "Databricks\nScoring (Cloud)", ha="center", va="center", fontsize=10, color=COLORS["text"])

    ax.add_patch(Rectangle((boxes["Decision"][0], boxes["Decision"][1]), boxes["Decision"][2], boxes["Decision"][3],
                           facecolor=COLORS["decision_fill"], edgecolor=COLORS["line"], linewidth=1.4))
    ax.text(boxes["Decision"][0] + boxes["Decision"][2] / 2, boxes["Decision"][1] + boxes["Decision"][3] / 2,
            "Decision Engine\n(On-Prem)", ha="center", va="center", fontsize=10, color=COLORS["text"])

    ax.add_patch(Rectangle((boxes["LLM"][0], boxes["LLM"][1]), boxes["LLM"][2], boxes["LLM"][3],
                           facecolor=COLORS["llm_fill"], edgecolor=COLORS["line"], linewidth=1.4))
    ax.text(boxes["LLM"][0] + boxes["LLM"][2] / 2, boxes["LLM"][1] + boxes["LLM"][3] / 2,
            "LLM\n(Cloud)", ha="center", va="center", fontsize=10, color=COLORS["text"])

    ax.add_patch(Rectangle((boxes["RM"][0], boxes["RM"][1]), boxes["RM"][2], boxes["RM"][3],
                           facecolor=COLORS["rm_fill"], edgecolor=COLORS["line"], linewidth=1.4))
    ax.text(boxes["RM"][0] + boxes["RM"][2] / 2, boxes["RM"][1] + boxes["RM"][3] / 2,
            "RM Workbench\n(On-Prem)", ha="center", va="center", fontsize=10, color=COLORS["text"])

    def arrow(x1: float, y1: float, x2: float, y2: float, label: str | None = None) -> None:
        ax.annotate(
            "",
            xy=(x2, y2),
            xytext=(x1, y1),
            arrowprops=dict(arrowstyle="->", linewidth=1.3, color=COLORS["line"]),
        )
        if label:
            ax.text((x1 + x2) / 2, (y1 + y2) / 2 + 0.02, label, ha="center", fontsize=8, color=COLORS["text"])

    arrow(0.18, 0.73, 0.24, 0.73, "PII JSON")
    arrow(0.46, 0.73, 0.52, 0.73, "masked")
    arrow(0.72, 0.73, 0.76, 0.73, "score + reasons")
    arrow(0.35, 0.62, 0.62, 0.28, "ENC tokens")
    arrow(0.62, 0.28, 0.46, 0.62, "masked text")
    arrow(0.72, 0.28, 0.76, 0.28, "de-masked")

    plt.title("Architecture Overview", fontsize=12)
    _save_fig("architecture_diagram.png")


def plot_sequence_diagram() -> None:
    fig, ax = plt.subplots(figsize=(8.5, 5.2))
    ax.axis("off")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)

    participants = [
        ("Client", 0.05),
        ("Service", 0.22),
        ("Cloud", 0.39),
        ("Decision", 0.56),
        ("LLM", 0.73),
        ("RM", 0.9),
    ]

    header_colors = {
        "Client": COLORS["client_fill"],
        "Service": COLORS["on_prem_fill"],
        "Cloud": COLORS["cloud_fill"],
        "Decision": COLORS["decision_fill"],
        "LLM": COLORS["llm_fill"],
        "RM": COLORS["rm_fill"],
    }

    for name, x in participants:
        ax.add_patch(
            Rectangle(
                (x - 0.055, 0.92),
                0.11,
                0.06,
                facecolor=header_colors.get(name, "white"),
                edgecolor=COLORS["line"],
                linewidth=1.2,
            )
        )
        ax.text(x, 0.95, name, ha="center", va="center", fontsize=9, color=COLORS["text"])
        ax.plot([x, x], [0.08, 0.92], color="#94A3B8", linewidth=0.8, linestyle="--")

    message_labels = [
        (0, 1, "TransactionIn (PII)"),
        (1, 1, "mask_transaction()"),
        (1, 1, "validate_egress (cloud)"),
        (1, 2, "masked payload"),
        (2, 1, "score + reasons"),
        (1, 3, "decision payload"),
        (1, 1, "build LLM prompt"),
        (1, 1, "validate_egress (llm)"),
        (1, 4, "LLM masked prompt"),
        (4, 1, "LLM masked response"),
        (1, 1, "unmask_text()"),
        (1, 5, "RM explanation"),
    ]

    start_y = 0.86
    step = 0.06
    messages = [(start_y - step * idx, *info) for idx, info in enumerate(message_labels)]

    def _message_color(src_idx: int, dst_idx: int) -> str:
        if src_idx == dst_idx == 1:
            return COLORS["on_prem_line"]
        if {src_idx, dst_idx} == {1, 2}:
            return COLORS["cloud_line"]
        if {src_idx, dst_idx} == {1, 3}:
            return COLORS["decision_line"]
        if {src_idx, dst_idx} == {1, 4}:
            return COLORS["llm_line"]
        if {src_idx, dst_idx} == {1, 5}:
            return COLORS["rm_line"]
        return COLORS["line"]

    for y, src_idx, dst_idx, label in messages:
        src_x = participants[src_idx][1]
        dst_x = participants[dst_idx][1]
        color = _message_color(src_idx, dst_idx)
        if src_idx == dst_idx:
            ax.annotate(
                "",
                xy=(src_x + 0.06, y),
                xytext=(src_x, y),
                arrowprops=dict(arrowstyle="->", linewidth=1.2, color=color),
            )
            ax.text(src_x + 0.065, y, label, fontsize=8, va="center", ha="left", color=COLORS["text"])
        else:
            ax.annotate(
                "",
                xy=(dst_x, y),
                xytext=(src_x, y),
                arrowprops=dict(arrowstyle="->", linewidth=1.2, color=color),
            )
            ax.text((src_x + dst_x) / 2, y + 0.018, label, fontsize=8, ha="center", color=COLORS["text"])

    plt.title("Sequence Diagram (E2E)", fontsize=12)
    _save_fig("sequence_diagram.png")


def main() -> None:
    plot_diagonal_scaling()
    plot_mcc_permutation_scatter()
    plot_aead_determinism()
    plot_llm_masked_exchange()
    plot_architecture_diagram()
    plot_sequence_diagram()


if __name__ == "__main__":
    main()
