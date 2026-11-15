# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 DigitGram
"""HashTally's Code-Cat scenes (SCENES; one is picked at random): the check (in ui_about.py, shared with TrustCopy), the magnifying
glass and the tower of hash blocks."""
import math
import random

import gi

gi.require_version("PangoCairo", "1.0")
from gi.repository import Pango, PangoCairo

from ui_about import CAT_W, COLORS, check, clamp, jump, lerp, nyan, shadow

COLORS.update({"o": (0.45, 0.3, 0.12)})


def label(cr, markup, x, y, font="Monospace Bold 10"):
    """Draw Pango markup with its top left at x, y; returns its pixel size."""
    layout = PangoCairo.create_layout(cr)
    layout.set_font_description(Pango.FontDescription(font))
    layout.set_markup(markup, -1)
    cr.move_to(x, y)
    PangoCairo.show_layout(cr, layout)
    return layout.get_pixel_size()


def rounded(cr, x, y, w, h, r=8):
    cr.new_sub_path()
    for cx, cy, a in ((x + w - r, y + r, -90), (x + w - r, y + h - r, 0), (x + r, y + h - r, 90), (x + r, y + r, 180)):
        cr.arc(cx, cy, r, math.radians(a), math.radians(a + 90))
    cr.close_path()


# ---------------------------------------------------------------------------------------------------------------------------------
# Magnifying glass: a panel with two hash strings pops up on the ground at the right. The cat sweeps a lens over them, finds the one
# character that differs, rings it in red, hops for joy and leaves. She stays on the ground the whole time.
G_BOX, G_OUT, G_SWEEP, G_FOUND, G_JOY, G_SINK, G_LEAP, G_END = 0.9, 1.3, 2.0, 3.7, 4.4, 5.0, 5.4, 6.4
LINE_1, LINE_2 = "a3f9c04e71bd", "a3f9c04e71bc"  # they differ in the last character


def lupe(st):
    size, lx, w, h, out_y = st.size, st.lx, st.w, st.h, st.out_y
    x_s = lx + size + 28  # where she stands
    bx, by, bw, bh = lx + size + 1, out_y - 76, 138, 56  # the panel, right at the logo's edge so the lens' handle stays inside the popover
    tx, ty1, ty2 = bx + 12, by + 7, by + 29  # the strings' top left, and the lines' tops
    cw = 8.0  # width of one character; measured on the first frame

    def texts(cr, t, found):
        """The two strings; the odd character of the second is red and ringed once it has been found."""
        cr.set_source_rgb(.9, .9, .95)
        label(cr, LINE_1, tx, ty1)
        label(cr, LINE_2[:-1] + ('<span foreground="#ff6b6b">%s</span>' % LINE_2[-1] if found else LINE_2[-1]), tx, ty2)
        if found:
            p = clamp((t - G_FOUND) / 0.2)
            cr.set_source_rgb(1, .3, .3)
            cr.set_line_width(2.5)
            cr.new_sub_path()
            cr.arc(tx + cw * 11.5, ty2 + 9, 8 + 6 * (1 - p) + 1.2 * math.sin(t * 12), 0, 2 * math.pi)
            cr.stroke()

    def magnifier(cr, cx, cy, k, t, found):
        """A magnifying glass icon: the strings seen through it are really enlarged; rim, handle and a glint on the glass."""
        r, zoom = 25 * k, 1.6
        cr.save()
        cr.new_sub_path()
        cr.arc(cx, cy, r, 0, 2 * math.pi)
        cr.clip()
        cr.set_source_rgb(.13, .13, .18)
        cr.paint()
        cr.translate(cx, cy)
        cr.scale(zoom, zoom)
        cr.translate(-cx, -cy)
        texts(cr, t, found)
        cr.restore()
        cr.new_sub_path()
        cr.arc(cx, cy, r, 0, 2 * math.pi)  # a faint blue tint on the glass
        cr.set_source_rgba(.7, .86, 1, .13)
        cr.fill()
        d = r * 0.707
        cr.set_line_cap(1)
        for width, colour in ((11, (.12, .09, .06)), (7, (.55, .38, .16))):  # the handle, outlined
            cr.set_line_width(width * k)
            cr.set_source_rgb(*colour)
            cr.move_to(cx + d + 2, cy + d + 2)
            cr.line_to(cx + d + 13 * k, cy + d + 13 * k)
            cr.stroke()
        for width, colour in ((6.5, (.12, .09, .06)), (4, (.8, .8, .86))):  # the rim, outlined
            cr.set_line_width(width * k)
            cr.set_source_rgb(*colour)
            cr.new_sub_path()
            cr.arc(cx, cy, r, 0, 2 * math.pi)
            cr.stroke()
        cr.set_line_width(3 * k)  # the glint
        cr.set_source_rgba(1, 1, 1, .75)
        cr.new_sub_path()
        cr.arc(cx, cy, r - 6 * k, math.radians(200), math.radians(245))
        cr.stroke()

    def draw(cr, t):
        nonlocal cw
        lift = squash = 0.0
        if G_JOY <= t < G_JOY + 0.4:  # a hop of joy
            f = (t - G_JOY) / 0.4
            lift, squash = 24 * 4 * f * (1 - f), -0.18 * math.sin(math.pi * f)
        pop = clamp((t - G_BOX) / 0.3)  # the panel pops up from its middle, a little overshoot, and shrinks away at the end
        sc = (1 - (1 - pop) ** 3) * (1 + 0.15 * math.sin(math.pi * pop)) * (1 - clamp((t - G_SINK) / 0.4) ** 2)
        if sc > 0.02:
            cr.save()
            cr.translate(bx + bw / 2, by + bh / 2)
            cr.scale(sc, sc)
            cr.translate(-bx - bw / 2, -by - bh / 2)
            rounded(cr, bx, by, bw, bh)
            cr.set_source_rgba(.13, .13, .18, .94)
            cr.fill()
            found = t >= G_FOUND
            cr.set_source_rgb(.9, .9, .95)
            cw = label(cr, "0", -50, -50)[0]  # off screen, just to measure
            texts(cr, t, found)
            lens_pop = clamp((t - G_SWEEP + 0.4) / 0.25)  # the magnifying glass floats in, over the strings
            if lens_pop > 0:
                f = clamp((t - G_SWEEP) / (G_FOUND - G_SWEEP))
                f = f * f * (3 - 2 * f)
                cx = lerp(tx + cw * 0.5, tx + cw * 11.5, f) + 2 * math.sin(t * 2.3) + (2 * math.sin(t * 9) if t >= G_FOUND else 0)
                cy = by + 28 + 3 * math.sin(t * 3.1)  # it drifts a little, as if swimming
                magnifier(cr, cx, cy, (1 - (1 - lens_pop) ** 3) * (1 + 0.15 * math.sin(math.pi * lens_pop)), t, found)
            cr.restore()
        if t < G_OUT:  # out from behind the logo
            cr.rectangle(lx + size, 0, w, h)
            cr.clip()
            x = lerp(lx + size - CAT_W + 20, x_s, t / G_OUT)
            shadow(cr, x, out_y)
            nyan(cr, x, out_y, t=t, run=True)
        elif t < G_LEAP:
            tau = t - G_OUT
            crouch = clamp((t - G_LEAP + 0.3) / 0.3) ** 2
            shadow(cr, x_s, out_y)
            nyan(cr, x_s, out_y - lift, t=t, alert=G_FOUND <= t < G_JOY, sx=1 + (squash + crouch * 0.32) * 0.6, sy=1 - squash - crouch * 0.32 - 0.1 * math.exp(-8 * tau) * math.cos(20 * tau))
        else:
            f = clamp((t - G_LEAP) / 0.6)
            x, y = jump(f, (x_s, out_y), (lx + size + 270, out_y), 44)
            nyan(cr, x, y, t=t, run=True, air=f <= 0.9, sx=1 - 0.12 * math.sin(math.pi * f), sy=1 + 0.25 * math.sin(math.pi * f), rot=0.45 * math.cos(math.pi * f))

    return draw, G_END


# ---------------------------------------------------------------------------------------------------------------------------------
# Tower: three blocks with hash characters rise behind the logo. The cat lands next to them, knocks them off one by one, and then
# looks as innocent as a cat can.
W_RISE, W_OUT, W_JUMP, W_LAND = 0.3, 1.3, 1.7, 2.2
W_SWIPES = (2.6, 3.0, 3.4)  # each knocks the top block off
W_TURN, W_LEAP, W_END = 3.9, 5.1, 6.0
BLOCKS = (("9", (0.95, 0.45, 0.4)), ("f", (0.98, 0.78, 0.3)), ("3", (0.4, 0.75, 0.5)))  # bottom to top
BS = 18  # block size


def tower(st):
    size, lx, top, w, h, sit_y, out_y = st.size, st.lx, st.top, st.w, st.h, st.sit_y, st.out_y
    tx, x_a = lx + 8, lx + 28
    rng = random.Random(4)  # the same tumble every time
    flight = [(rng.uniform(-170, -90), rng.uniform(-260, -170), rng.uniform(-9, 9)) for _ in BLOCKS]

    def block(cr, i, x, y, rot=0.0):
        letter, color = BLOCKS[i]
        cr.save()
        cr.translate(x + BS / 2, y + BS / 2)
        cr.rotate(rot)
        cr.rectangle(-BS / 2, -BS / 2, BS, BS)
        cr.set_source_rgb(*color)
        cr.fill_preserve()
        cr.set_source_rgb(.15, .15, .2)
        cr.set_line_width(2)
        cr.stroke()
        cr.set_source_rgb(.1, .1, .15)
        label(cr, letter, -4.5, -8.5, "Monospace Bold 10")
        cr.restore()

    def draw(cr, t):
        rise = 1 - (1 - clamp((t - W_RISE) / 0.7)) ** 3
        for i in range(len(BLOCKS)):
            launched = W_SWIPES[len(BLOCKS) - 1 - i] + 0.12  # the top block goes first
            y = top - BS * (i + 1) * rise
            if t < launched:
                cr.save()
                cr.rectangle(tx - 2, 0, BS + 4, top)  # comes from behind the logo
                cr.clip()
                block(cr, i, tx, y)
                cr.restore()
            else:
                age = t - launched
                vx, vy, spin = flight[i]
                block(cr, i, tx + vx * age, y + vy * age + 700 * age * age, spin * age)
        if t < W_OUT:
            cr.rectangle(lx + size, 0, w, h)
            cr.clip()
            x = lerp(lx + size - CAT_W + 20, lx + size + 28, t / W_OUT)
            shadow(cr, x, out_y)
            nyan(cr, x, out_y, t=t, run=True)
        elif t < W_JUMP:
            shadow(cr, lx + size + 28, out_y)
            c = clamp((t - W_JUMP + 0.25) / 0.25) * 0.3
            nyan(cr, lx + size + 28, out_y, flip=True, t=t, alert=True, sx=1 + c * 0.6, sy=1 - c, rot=math.sin(t * 45) * 0.06 * c / 0.3)
        elif t < W_LAND:
            f = (t - W_JUMP) / 0.5
            x, y = jump(f, (lx + size + 28, out_y), (x_a, sit_y), 24)
            nyan(cr, x, y, flip=True, t=t, run=True, air=True, sx=1 - 0.15 * math.sin(math.pi * f), sy=1 + 0.25 * math.sin(math.pi * f), rot=0.4 * math.cos(math.pi * f))
        elif t < W_LEAP:
            tau = t - W_LAND
            land = 0.3 * math.exp(-9 * tau) * math.cos(22 * tau)
            pawing = any(t0 <= t < t0 + 0.24 for t0 in W_SWIPES) and int((t - 2.6) / 0.12) % 2 == 0
            crouch = clamp((t - W_LEAP + 0.3) / 0.3) ** 2
            nyan(cr, x_a, sit_y, flip=t < W_TURN, t=t, swipe=pawing, sleep=W_TURN + 0.15 <= t < W_LEAP - 0.35,  # eyes shut: who, me?
                 sx=1 + land * 0.6 + crouch * 0.18, sy=1 - land - crouch * 0.3)
        else:
            f = clamp((t - W_LEAP) / 0.6)
            x, y = jump(f, (x_a, sit_y), (lx + size + 270, out_y), 44)
            nyan(cr, x, y, t=t, run=True, air=f <= 0.9, sx=1 - 0.12 * math.sin(math.pi * f), sy=1 + 0.25 * math.sin(math.pi * f), rot=0.45 * math.cos(math.pi * f))

    return draw, W_END


SCENES = (check, lupe, tower)
