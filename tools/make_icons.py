#!/usr/bin/env python3
"""Generator ikon PWA Q-EKH — PNG RGBA murni Python (tanpa PIL).
Menggambar: kotak rounded gelap, cincin gradasi cyan->violet, lubang kunci,
dan beberapa bintang kecil. Render 2x lalu downsample (anti-aliasing)."""
import math
import struct
import zlib

CYAN = (0x67, 0xE8, 0xF9)
VIOLET = (0x8B, 0x5C, 0xF6)
BG_TOP = (0x14, 0x1E, 0x38)
BG_BOT = (0x07, 0x0B, 0x16)


def lerp(a, b, t):
    return tuple(int(round(a[i] + (b[i] - a[i]) * t)) for i in range(3))


def render(S, margin=0.0):
    """Render ke buffer RGBA ukuran S x S (S sudah supersampled).
    margin > 0 menghasilkan varian "maskable": latar digambar penuh sampai
    tepi (bleed) dan seluruh elemen dipetakan ke area konten tengah
    (1 - 2*margin) — aman dipotong lingkaran/squircle oleh Android."""
    buf = bytearray(S * S * 4)
    cx = cy = S / 2
    ring_r = S * 0.30
    ring_w = S * 0.052
    corner = S * 0.22
    kh_cy = S * 0.415        # pusat lingkaran lubang kunci
    kh_r = S * 0.088
    stem_w = S * 0.055
    stem_top = kh_cy + kh_r * 0.35
    stem_bot = S * 0.66
    bar_w = S * 0.11
    bar_cy = S * 0.575
    bar_h = S * 0.045
    stars = [(0.20, 0.16, 0.012, CYAN), (0.82, 0.13, 0.010, VIOLET),
             (0.88, 0.80, 0.012, CYAN), (0.14, 0.78, 0.010, VIOLET)]
    span = 1.0 - 2 * margin

    for y in range(S):
        ny = y / S
        row = y * S * 4
        for x in range(S):
            nx = x / S
            i = row + x * 4
            if margin > 0:
                # petakan piksel ke ruang konten [0, S]; di luar = hanya latar
                px = (nx - margin) / span * S
                py = (ny - margin) / span * S
            else:
                # mask rounded-rect (SDF)
                qx = abs(x - cx) - (S / 2 - corner)
                qy = abs(y - cy) - (S / 2 - corner)
                d = math.hypot(max(qx, 0), max(qy, 0)) + min(max(qx, qy), 0) - corner
                if d > 0:
                    continue  # transparan di luar sudut
                px, py = x, y
            # latar: gradasi vertikal
            col = lerp(BG_TOP, BG_BOT, ny)
            a = 255
            if 0 <= px <= S and 0 <= py <= S:
                dx = px - cx
                dy = py - cy
                dist = math.hypot(dx, dy)
                # cincin gradasi sudut cyan->violet
                if abs(dist - ring_r) <= ring_w / 2:
                    ang = (math.atan2(dy, dx) + math.pi) / (2 * math.pi)
                    col = lerp(CYAN, VIOLET, ang)
                # lubang kunci: lingkaran + batang + palang
                if math.hypot(dx, py - kh_cy) <= kh_r:
                    col = lerp(CYAN, VIOLET, nx)
                if stem_top <= py <= stem_bot and abs(dx) <= stem_w / 2:
                    col = lerp(CYAN, VIOLET, nx)
                if abs(py - bar_cy) <= bar_h / 2 and abs(dx) <= bar_w / 2:
                    col = lerp(CYAN, VIOLET, nx)
                # bintang kecil
                for sx, sy, sr, scol in stars:
                    if math.hypot(px - sx * S, py - sy * S) <= sr * S:
                        col = scol
            buf[i] = col[0]
            buf[i + 1] = col[1]
            buf[i + 2] = col[2]
            buf[i + 3] = a
    return buf


def downsample(buf, S, T):
    """Rata-rata blok k x k dari S ke T (k = S // T)."""
    k = S // T
    out = bytearray(T * T * 4)
    for y in range(T):
        for x in range(T):
            r = g = b = a = 0
            for yy in range(y * k, y * k + k):
                base = (yy * S + x * k) * 4
                for xx in range(k):
                    i = base + xx * 4
                    r += buf[i]; g += buf[i + 1]; b += buf[i + 2]; a += buf[i + 3]
            n = k * k
            j = (y * T + x) * 4
            out[j] = r // n; out[j + 1] = g // n; out[j + 2] = b // n; out[j + 3] = a // n
    return out


def write_png(path, buf, W, H=None):
    if H is None:
        H = W
    raw = b"".join(b"\x00" + bytes(buf[y * W * 4:(y + 1) * W * 4]) for y in range(H))
    def chunk(tag, data):
        c = tag + data
        return struct.pack(">I", len(data)) + c + struct.pack(">I", zlib.crc32(c))
    png = (b"\x89PNG\r\n\x1a\n"
           + chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 6, 0, 0, 0))
           + chunk(b"IDAT", zlib.compress(raw, 9))
           + chunk(b"IEND", b""))
    with open(path, "wb") as f:
        f.write(png)


MASKABLE_MARGIN = 0.10  # konten di 80% area tengah (safe zone maskable)

for size in (192, 512):
    SS = size * 2
    img = downsample(render(SS), SS, size)
    write_png(f"icons/icon-{size}.png", img, size)
    print(f"icons/icon-{size}.png selesai")
    mask = downsample(render(SS, MASKABLE_MARGIN), SS, size)
    write_png(f"icons/icon-maskable-{size}.png", mask, size)
    print(f"icons/icon-maskable-{size}.png selesai (margin {MASKABLE_MARGIN:.0%}/sisi)")

# favicon turunan (A.3): ukuran kecil butuh supersample lebih tinggi
for size in (16, 32):
    SS = size * 8
    write_png(f"icons/favicon-{size}.png", downsample(render(SS), SS, size), size)
    print(f"icons/favicon-{size}.png selesai")


# ======================================================================
# A.2 — SOCIAL PREVIEW / OG IMAGE (1280x640), murni Python tanpa PIL
# ======================================================================
# Font bitmap 5x7 (baris atas -> bawah, '#' = pixel nyala). Karakter tak
# dikenal dirender kosong selebar spasi.
FONT = {
    'A': [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    'B': ["####.", "#...#", "#...#", "####.", "#...#", "#...#", "####."],
    'C': [".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."],
    'D': ["###..", "#..#.", "#...#", "#...#", "#...#", "#..#.", "###.."],
    'E': ["#####", "#....", "#....", "####.", "#....", "#....", "#####"],
    'F': ["#####", "#....", "#....", "####.", "#....", "#....", "#...."],
    'G': [".###.", "#...#", "#....", "#.###", "#...#", "#...#", ".###."],
    'H': ["#...#", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    'I': ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"],
    'J': ["..###", "...#.", "...#.", "...#.", "...#.", "#..#.", ".##.."],
    'K': ["#...#", "#..#.", "#.#..", "##...", "#.#..", "#..#.", "#...#"],
    'L': ["#....", "#....", "#....", "#....", "#....", "#....", "#####"],
    'M': ["#...#", "##.##", "#.#.#", "#.#.#", "#...#", "#...#", "#...#"],
    'N': ["#...#", "##..#", "#.#.#", "#..##", "#...#", "#...#", "#...#"],
    'O': [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    'P': ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."],
    'Q': [".###.", "#...#", "#...#", "#...#", "#.#.#", "#..#.", ".##.#"],
    'R': ["####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"],
    'S': [".####", "#....", "#....", ".###.", "....#", "....#", "####."],
    'T': ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "..#.."],
    'U': ["#...#", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    'V': ["#...#", "#...#", "#...#", "#...#", "#...#", ".#.#.", "..#.."],
    'W': ["#...#", "#...#", "#...#", "#.#.#", "#.#.#", "##.##", "#...#"],
    'X': ["#...#", "#...#", ".#.#.", "..#..", ".#.#.", "#...#", "#...#"],
    'Y': ["#...#", "#...#", ".#.#.", "..#..", "..#..", "..#..", "..#.."],
    'Z': ["#####", "....#", "...#.", "..#..", ".#...", "#....", "#####"],
    '0': [".###.", "#...#", "#..##", "#.#.#", "##..#", "#...#", ".###."],
    '1': ["..#..", ".##..", "..#..", "..#..", "..#..", "..#..", "#####"],
    '2': [".###.", "#...#", "....#", "...#.", "..#..", ".#...", "#####"],
    '3': ["####.", "....#", "....#", ".###.", "....#", "....#", "####."],
    '4': ["...#.", "..##.", ".#.#.", "#..#.", "#####", "...#.", "...#."],
    '5': ["#####", "#....", "####.", "....#", "....#", "#...#", ".###."],
    '6': [".###.", "#....", "#....", "####.", "#...#", "#...#", ".###."],
    '7': ["#####", "....#", "...#.", "..#..", "..#..", "..#..", "..#.."],
    '8': [".###.", "#...#", "#...#", ".###.", "#...#", "#...#", ".###."],
    '9': [".###.", "#...#", "#...#", ".####", "....#", "....#", ".###."],
    '-': [".....", ".....", ".....", "#####", ".....", ".....", "....."],
    '.': [".....", ".....", ".....", ".....", ".....", ".##..", ".##.."],
    ',': [".....", ".....", ".....", ".....", "..#..", "..#..", ".#..."],
    ':': [".....", ".##..", ".##..", ".....", ".##..", ".##..", "....."],
    '%': ["##..#", "##.#.", "...#.", "..#..", ".#...", "#.##.", "#..##"],
    '&': [".##..", "#..#.", "#.#..", ".#...", "#.#.#", "#..#.", ".##.#"],
    '/': ["....#", "....#", "...#.", "..#..", ".#...", "#....", "#...."],
    '+': [".....", "..#..", "..#..", "#####", "..#..", "..#..", "....."],
    '(': ["...#.", "..#..", ".#...", ".#...", ".#...", "..#..", "...#."],
    ')': [".#...", "..#..", "...#.", "...#.", "...#.", "..#..", ".#..."],
    ' ': [".....", ".....", ".....", ".....", ".....", ".....", "....."],
}


def text_width(text, scale):
    return max(0, len(text) * 6 - 1) * scale


def draw_text(buf, W, H, x0, y0, text, scale, col):
    for k, ch in enumerate(text.upper()):
        glyph = FONT.get(ch, FONT[' '])
        gx = x0 + k * 6 * scale
        for gy, rowbits in enumerate(glyph):
            for gxbit, bit in enumerate(rowbits):
                if bit != '#':
                    continue
                for yy in range(scale):
                    py = y0 + gy * scale + yy
                    if py < 0 or py >= H:
                        continue
                    row = py * W * 4
                    for xx in range(scale):
                        px = gx + gxbit * scale + xx
                        if 0 <= px < W:
                            i = row + px * 4
                            buf[i], buf[i + 1], buf[i + 2] = col[0], col[1], col[2]


def blend_rect(buf, W, H, x0, y0, w, h, col, alpha):
    for y in range(max(0, y0), min(H, y0 + h)):
        row = y * W * 4
        for x in range(max(0, x0), min(W, x0 + w)):
            i = row + x * 4
            buf[i] = int(buf[i] * (1 - alpha) + col[0] * alpha)
            buf[i + 1] = int(buf[i + 1] * (1 - alpha) + col[1] * alpha)
            buf[i + 2] = int(buf[i + 2] * (1 - alpha) + col[2] * alpha)


def blend_pixel(buf, W, H, x, y, col, alpha):
    if 0 <= x < W and 0 <= y < H:
        i = (y * W + x) * 4
        buf[i] = int(buf[i] * (1 - alpha) + col[0] * alpha)
        buf[i + 1] = int(buf[i + 1] * (1 - alpha) + col[1] * alpha)
        buf[i + 2] = int(buf[i + 2] * (1 - alpha) + col[2] * alpha)


def draw_line(buf, W, H, x0, y0, x1, y1, col, alpha):
    dx, dy = abs(x1 - x0), -abs(y1 - y0)
    sx, sy = (1 if x0 < x1 else -1), (1 if y0 < y1 else -1)
    err = dx + dy
    while True:
        blend_pixel(buf, W, H, x0, y0, col, alpha)
        if x0 == x1 and y0 == y1:
            break
        e2 = 2 * err
        if e2 >= dy:
            err += dy
            x0 += sx
        if e2 <= dx:
            err += dx
            y0 += sy


def render_og(W=1280, H=640):
    """Kanvas social preview: latar gradasi + konstelasi deterministik,
    perisai (hasil render() ikon) di kiri, teks bitmap di kanan."""
    buf = bytearray(W * H * 4)
    for y in range(H):
        ny = y / H
        row = y * W * 4
        for x in range(W):
            i = row + x * 4
            # latar gradasi + cahaya lembut dari kiri atas
            col = lerp(BG_TOP, BG_BOT, ny)
            glow = max(0.0, 1.0 - math.hypot(x - W * 0.18, y - H * 0.1) / (W * 0.55))
            col = lerp(col, CYAN, glow * 0.10)
            buf[i], buf[i + 1], buf[i + 2], buf[i + 3] = col[0], col[1], col[2], 255

    # konstelasi deterministik (LCG sederhana supaya hasil stabil)
    seed = 20261009
    def rnd():
        nonlocal seed
        seed = (seed * 1103515245 + 12345) & 0x7fffffff
        return seed / 0x7fffffff
    pts = [(rnd() * W, rnd() * H) for _ in range(70)]
    for i, (ax, ay) in enumerate(pts):
        for bx, by in pts[i + 1:]:
            if math.hypot(ax - bx, ay - by) < 150:
                draw_line(buf, W, H, int(ax), int(ay), int(bx), int(by), VIOLET, 0.18)
    for px, py in pts:
        r = 2 if rnd() < 0.7 else 3
        col = CYAN if rnd() < 0.5 else VIOLET
        blend_rect(buf, W, H, int(px) - r // 2, int(py) - r // 2, r, r, col, 0.75)

    # perisai: render ikon 384 lalu blit (nearest) ke panel kiri
    icon = render(384 * 2)          # supersample 2x bawaan
    icon = downsample(icon, 384 * 2, 384)
    IX, IY, IS = 84, (H - 384) // 2, 384
    for y in range(IS):
        for x in range(IS):
            si = (y * IS + x) * 4
            a = icon[si + 3]
            if a == 0:
                continue
            di = ((IY + y) * W + (IX + x)) * 4
            buf[di], buf[di + 1], buf[di + 2], buf[di + 3] = icon[si], icon[si + 1], icon[si + 2], 255

    # teks di panel kanan (mulai x=540) — kursor y berjalan supaya tak terpotong
    TX = 540
    ty = 108
    draw_text(buf, W, H, TX, ty, "Q-EKH", 22, CYAN)
    ty += 22 * 7 + 24
    draw_text(buf, W, H, TX, ty, "PROTOCOL", 12, VIOLET)
    ty += 12 * 7 + 24
    blend_rect(buf, W, H, TX, ty, 6 * 12 * 8 - 12, 4, CYAN, 0.85)
    ty += 28
    draw_text(buf, W, H, TX, ty, "ENKRIPSI HIBRIDA", 6, (0xEE, 0xF2, 0xFF))
    ty += 52
    draw_text(buf, W, H, TX, ty, "PASCA-KUANTUM", 6, (0xEE, 0xF2, 0xFF))
    ty += 64
    draw_text(buf, W, H, TX, ty, "100% LOKAL & OFFLINE", 5, (0xA8, 0xB3, 0xCF))
    ty += 48
    draw_text(buf, W, H, TX, ty, "X25519 + ML-KEM-768", 5, (0xA8, 0xB3, 0xCF))
    return buf


og = render_og()
write_png("social-preview.png", og, 1280, 640)
print("social-preview.png selesai (1280x640)")
