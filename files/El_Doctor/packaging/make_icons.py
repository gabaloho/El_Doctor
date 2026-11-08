#!/usr/bin/env python3
"""Generate the El Doctor application icon in every format the installers need (Pillow, build-time only).

    python packaging/make_icons.py

Writes packaging/assets/ (eldoctor.ico for Windows, eldoctor.icns for macOS, eldoctor-<size>.png for Linux
desktops) and eldoctor/data/icons/ (window icon used by the GUI).  The generated files are committed; run this
again only to change the design.
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFilter

ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "packaging" / "assets"
APP_ICONS = ROOT / "eldoctor" / "data" / "icons"
S = 1024                                                   # master size; everything else is downsampled


def master() -> Image.Image:
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    # rounded-square background with a vertical blue -> teal gradient
    grad = Image.new("RGBA", (S, S))
    gd = ImageDraw.Draw(grad)
    top, bottom = (23, 76, 160), (16, 150, 150)
    for y in range(S):
        t = y / (S - 1)
        gd.line([(0, y), (S, y)], fill=tuple(int(a + (b - a) * t) for a, b in zip(top, bottom)) + (255,))
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle([40, 40, S - 40, S - 40], radius=210, fill=255)
    img.paste(grad, (0, 0), mask)
    # shield with a soft shadow
    shield = [(512, 190), (790, 290), (790, 520), (760, 640), (690, 740), (600, 815), (512, 860),
              (424, 815), (334, 740), (264, 640), (234, 520), (234, 290)]
    shadow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    ImageDraw.Draw(shadow).polygon([(x + 10, y + 18) for x, y in shield], fill=(0, 0, 0, 90))
    img.alpha_composite(shadow.filter(ImageFilter.GaussianBlur(18)))
    d = ImageDraw.Draw(img)
    d.polygon(shield, fill=(255, 255, 255, 255))
    # medical cross ("doctor") in the shield
    c = (220, 53, 69, 255)
    d.rounded_rectangle([452, 330, 572, 690], radius=22, fill=c)
    d.rounded_rectangle([332, 450, 692, 570], radius=22, fill=c)
    return img


def main() -> None:
    ASSETS.mkdir(parents=True, exist_ok=True)
    APP_ICONS.mkdir(parents=True, exist_ok=True)
    big = master()
    sizes = [16, 24, 32, 48, 64, 128, 256, 512]
    imgs = {s: big.resize((s, s), Image.LANCZOS) for s in sizes}
    for s in (48, 64, 128, 256, 512):
        imgs[s].save(ASSETS / f"eldoctor-{s}.png", optimize=True)
    big.save(ASSETS / "eldoctor-1024.png", optimize=True)
    imgs[256].save(ASSETS / "eldoctor.ico", sizes=[(s, s) for s in (16, 24, 32, 48, 64, 128, 256)])
    big.save(ASSETS / "eldoctor.icns")
    imgs[64].save(APP_ICONS / "eldoctor-64.png", optimize=True)
    imgs[256].save(APP_ICONS / "eldoctor-256.png", optimize=True)
    print("icons written to", ASSETS, "and", APP_ICONS)


if __name__ == "__main__":
    main()
