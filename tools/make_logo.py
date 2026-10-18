"""Genera el logo de NetAnalyzer: resources/netanalyzer.ico (icono del .exe) y resources/logo.png.

Uso:  python tools/make_logo.py      (requiere Pillow: pip install pillow)

El diseño es geométrico para poder reproducirlo también en C++ (setWindowIcon en
src/app/main.cpp, usado en Linux): si cambias algo aquí, cámbialo allí también.
  - Cuadrado redondeado con degradado diagonal azul -> violeta.
  - Anillo tenue de "radar" alrededor del nodo central.
  - Nodo central y tres satélites unidos por enlaces; el de abajo, verde (conexión activa).
"""
import math
import os

from PIL import Image, ImageDraw

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
S = 1024  # lienzo de trabajo; se reduce con antialiasing a cada tamaño

TOP = (64, 140, 255)      # degradado: arriba-izquierda
BOTTOM = (124, 92, 250)   # abajo-derecha
GREEN = (74, 222, 128)
WHITE = (255, 255, 255)

RADIUS = 0.225            # redondeo del cuadrado
HUB = (0.5, 0.5, 0.105)   # x, y, radio
SAT_R = 0.078
SAT_DIST = 0.315           # sobre el anillo
SAT_ANGLES = (-150, -30, 90)  # grados; 90 = abajo (verde)
LINK_W = 0.044
RING_R, RING_W, RING_ALPHA = 0.315, 0.03, 0.38


def draw(size):
    img = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # Fondo: degradado diagonal recortado por el cuadrado redondeado.
    grad = Image.new("RGBA", (S, S))
    gp = grad.load()
    for y in range(S):
        for x in range(S):
            t = (x + y) / (2 * (S - 1))
            gp[x, y] = tuple(int(TOP[i] + (BOTTOM[i] - TOP[i]) * t) for i in range(3)) + (255,)
    mask = Image.new("L", (S, S), 0)
    ImageDraw.Draw(mask).rounded_rectangle((0, 0, S - 1, S - 1), radius=int(RADIUS * S), fill=255)
    img.paste(grad, (0, 0), mask)

    # Anillo de radar (blanco translúcido).
    ring = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    rd = ImageDraw.Draw(ring)
    c, r, w = S / 2, RING_R * S, RING_W * S
    rd.ellipse((c - r, c - r, c + r, c + r), outline=WHITE + (int(255 * RING_ALPHA),), width=int(w))
    img = Image.alpha_composite(img, ring)

    d = ImageDraw.Draw(img)
    hx, hy, hr = HUB[0] * S, HUB[1] * S, HUB[2] * S
    sats = []
    for a in SAT_ANGLES:
        rad = math.radians(a)
        sats.append((hx + math.cos(rad) * SAT_DIST * S, hy + math.sin(rad) * SAT_DIST * S, a == 90))
    for sx, sy, _ in sats:
        d.line((hx, hy, sx, sy), fill=WHITE, width=int(LINK_W * S))
    d.ellipse((hx - hr, hy - hr, hx + hr, hy + hr), fill=WHITE)
    sr = SAT_R * S
    for sx, sy, green in sats:
        d.ellipse((sx - sr, sy - sr, sx + sr, sy + sr), fill=GREEN if green else WHITE)

    return img.resize((size, size), Image.LANCZOS)


def main():
    out = os.path.join(ROOT, "resources")
    big = draw(512)
    big.save(os.path.join(out, "logo.png"))
    sizes = [256, 128, 64, 48, 32, 24, 16]
    big.resize((256, 256), Image.LANCZOS).save(
        os.path.join(out, "netanalyzer.ico"), sizes=[(s, s) for s in sizes])
    print("resources/logo.png y resources/netanalyzer.ico generados")


if __name__ == "__main__":
    main()
