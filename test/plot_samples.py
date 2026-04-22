#!/usr/bin/env python3
# Plot byte-pair scatter and heatmap for TRNG sample files.
#
# Usage:
#   python3 plot_samples.py <file.bin> [--no-show]
#   python3 plot_samples.py raw.bin whitened.bin [--no-show]
#
# Single file:  produces <file>-scatter.png and <file>-heatmap.png
# Two files:    side-by-side comparison (raw left, whitened right)
#
# The scatter plot (byte[i] vs byte[i+1]) reveals sequential correlation.
# Ideal random data fills the plane uniformly; raw INM output shows a
# visible grid pattern from the multiplier's preferred bit states.

import sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib import cm
from pathlib import Path


def load_bytes(path, max_bytes=0):
    data = np.fromfile(path, dtype=np.uint8)
    if max_bytes > 0 and len(data) > max_bytes:
        data = data[:max_bytes]
    return data


def scatter_ax(ax, data, title):
    """Byte-pair scatter on an existing axes."""
    n = min(len(data) - 1, 2000)
    x = data[:n].astype(np.float64)
    y = data[1:n + 1].astype(np.float64)
    ax.scatter(x, y, s=4, alpha=0.6, edgecolors="none")
    ax.set_xlim(0, 255)
    ax.set_ylim(0, 255)
    ax.set_xlabel("byte[i]")
    ax.set_ylabel("byte[i+1]")
    ax.set_title(title)
    ax.grid(True, alpha=0.3)
    ax.set_aspect("equal")


def heatmap_ax(ax, data, title):
    """Byte-value heatmap on an existing axes."""
    side = int(np.sqrt(len(data)))
    if side < 10:
        return
    trimmed = data[:side * side].reshape(side, side)
    cax = ax.imshow(trimmed, interpolation="nearest", cmap=cm.afmhot,
                    vmin=0, vmax=255)
    ax.set_xlabel("samples")
    ax.set_ylabel("samples")
    ax.set_title(title)
    plt.colorbar(cax, ax=ax, ticks=[0, 127, 255])


def plot_single(path, show):
    name = Path(path).name
    data = load_bytes(path)
    if len(data) < 100:
        print(f"skip {path}: only {len(data)} bytes", file=sys.stderr)
        return

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
    scatter_ax(ax1, data, f"{name} — byte-pair scatter")
    heatmap_ax(ax2, data, f"{name} — heatmap")
    fig.tight_layout()

    out = str(Path(path).with_suffix("")) + "-plots.png"
    fig.savefig(out, dpi=150)
    print(f"saved {out}")
    if show:
        plt.show()
    plt.close(fig)


def plot_compare(raw_path, white_path, show):
    raw = load_bytes(raw_path)
    white = load_bytes(white_path)
    rname = Path(raw_path).name
    wname = Path(white_path).name

    fig, axes = plt.subplots(2, 2, figsize=(12, 10))
    scatter_ax(axes[0][0], raw, f"{rname} — scatter (raw)")
    scatter_ax(axes[0][1], white, f"{wname} — scatter (whitened)")
    heatmap_ax(axes[1][0], raw, f"{rname} — heatmap (raw)")
    heatmap_ax(axes[1][1], white, f"{wname} — heatmap (whitened)")
    fig.tight_layout()

    out = str(Path(raw_path).parent / "raw-vs-whitened-plots.png")
    fig.savefig(out, dpi=150)
    print(f"saved {out}")
    if show:
        plt.show()
    plt.close(fig)


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("-")]
    show = "--no-show" not in sys.argv

    if len(args) == 0:
        print("usage: plot_samples.py <file.bin> [file2.bin] [--no-show]",
              file=sys.stderr)
        sys.exit(1)
    elif len(args) == 1:
        plot_single(args[0], show)
    else:
        plot_compare(args[0], args[1], show)
