# Rekall Memory Forensics
#
# Copyright 2015 Google Inc. All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

"""
Various functions for handling colors. Used mainly for visualizing output
of plugins with heatmaps (for now).

Most of the code below is made to match this color chart:
http://en.wikipedia.org/wiki/File:Xterm_256color_chart.svg

The colorspace conversions are thin wrappers around colorsys, except for
the code to handle XTerm colors, which is my own work.
"""
__author__ = "Adam Sindelar <adamsh@google.com>"

import colorsys


def ArbitraryStepFunction(value, steps):
    for step, ceiling in enumerate(steps):
        if int(value) <= ceiling:
            return step

    raise ValueError("Maximum value of %d exceeded with %d." % (steps[-1],
                                                                value))


XTERM16 = ((0x00, 0x00, 0x00), (0x80, 0x00, 0x00), (0x00, 0x80, 0x00),
           (0x80, 0x80, 0x00), (0x00, 0x00, 0x80), (0x80, 0x00, 0x80),
           (0x00, 0x80, 0x80), (0xc0, 0xc0, 0xc0), (0x80, 0x80, 0x80),
           (0xff, 0x00, 0x00), (0x00, 0xff, 0x00), (0xff, 0xff, 0x00),
           (0x00, 0x00, 0xff), (0xff, 0x00, 0xff), (0x00, 0xff, 0xff),
           (0xff, 0xff, 0xff))
"""XTerm has 16 special colors, as listed above."""


XTERM_CHANNEL_STEPS = [0, 0x5f, 0x87, 0xaf, 0xd7, 0xff]
"""XTerm color space is sparse at low luminosity."""


def ChannelStepFunction(intensity):
    return ArbitraryStepFunction(intensity, XTERM_CHANNEL_STEPS)


def GreyscaleStepFunction(intensity):
    return ArbitraryStepFunction(intensity, xrange(0x8, 0xef, 0xa))


# Color-space conversions:


def RGBToXTerm(red, green, blue):
    """Convert RGB values (0-255) to the closes XTerm color."""
    sred = ChannelStepFunction(red)
    sgreen = ChannelStepFunction(green)
    sblue = ChannelStepFunction(blue)

    # Greyscale starts at xterm 232 and has 12 shades. Black and white are part
    # of the 16-color range at the base of the spectrum.
    if sred == sgreen == sblue:
        avg = (red + green + blue) / 3
        if avg < 0x8:
            return 0
        elif avg > 0xee:
            return 15
        else:
            return 232 + GreyscaleStepFunction(avg)

    return (16  # base offset
            + ChannelStepFunction(blue)  # Blue increases in the inner loop.
            + ChannelStepFunction(green) * 6  # Green increases in the middle.
            + ChannelStepFunction(red) * 6 ** 2)  # Outer loop for red.


def XTermToRGB(xterm):
    """Convert the XTerm color (0-255) to an RGB equivalent."""
    if xterm < 16:
        return XTERM16[xterm]

    if xterm >= 232:
        # Greyscale
        value = (xterm - 231) * 0x08
        return value, value, value

    xterm -= 16  # Base of 256-color space.
    red, r = divmod(xterm, 6 ** 2)
    green, blue = divmod(r, 6)

    return (XTERM_CHANNEL_STEPS[red],
            XTERM_CHANNEL_STEPS[green],
            XTERM_CHANNEL_STEPS[blue])


def RGBToHSL(red, green, blue):
    hue, luminosity, saturation = colorsys.rgb_to_hls(
        float(red) / 0xff, float(green) / 0xff, float(blue) / 0xff)

    return hue, saturation, luminosity


def RGBToYIQ(red, green, blue):
    return colorsys.rgb_to_yiq(
        float(red) / 0xff, float(green) / 0xff, float(blue) / 0xff)


def HSLToRGB(hue, saturation, luminosity):
    red, green, blue = colorsys.hls_to_rgb(hue, luminosity, saturation)
    return int(red * 0xff), int(green * 0xff), int(blue * 0xff)


def YIQToRGB(y, i, q):
    red, green, blue = colorsys.yiq_to_rgb(y, i, q)
    return int(red * 0xff), int(green * 0xff), int(blue * 0xff)


# Text-color heuristics:


def YIQTextForBackground(y, i, q):
    """Compute the foreground color, given the background color."""
    # Y is luma, which is basically the sum of gamma-adjusted RGB channels.
    # The Y channel is intentionally weighted towards the red end of the
    # spectrum and high luminosities; I and Q are chromatic channels and carry
    # no luminosity information.
    # Perceptually, white text on red background of equivalent luminosity
    # is more readable than white text on blue or green backgrounds, hence
    # the formula below. (For greyscale this is basically identical to
    # the HSL luminosity channel, using threshold of .5, because of the gamma
    # compression's nonlinearity.)
    return (0, 0, 0) if (y * 2 - i - q) > .8 else (1, 0, 0)


def RGBTextForBackground(red, green, blue):
    """Compute the foreground color, given the background color."""
    hsl = RGBToYIQ(red, green, blue)
    text = YIQTextForBackground(*hsl)
    r, g, b = YIQToRGB(*text)
    return r, g, b


def XTermTextForBackground(xterm):
    """Compute the foreground color, given the background color."""
    rgb = XTermToRGB(xterm)
    fg = RGBTextForBackground(*rgb)
    return RGBToXTerm(*fg)


# Functions to color heatmaps:


def BlendRGB(x, y, wx=1, wy=1):
    """Blend RGB colors x and y, optionally using assigned weights wx and wy."""
    t = wx + wy
    return ((x[0] * wx + y[0] * wy) / t,
            (x[1] * wx + y[1] * wy) / t,
            (x[2] * wx + y[2] * wy) / t)


def HeatToHSL(heat, greyscale=False):
    """Given heat (0-1.0), compute the color to represent it on a heatmap.

    Arguments:
        Greyscale: If True, use luminosity instead of hue.
    """
    if greyscale:
        saturation = 0
        hue = 0
        luminosity = heat
    else:
        saturation = 1.0
        luminosity = .5
        hue = .5 - (heat * .5)

    return hue, saturation, luminosity


def HeatToRGB(heat, greyscale=False):
    return HSLToRGB(*HeatToHSL(heat, greyscale))


def HeatToXTerm(heat, greyscale=False):
    hsl = HeatToHSL(heat, greyscale)
    rgb = HSLToRGB(*hsl)
    xterm = RGBToXTerm(*rgb)

    return xterm
