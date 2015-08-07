# Rekall Memory Forensics
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

"""This module contains general-purpose algorithms and data structures."""

__author__ = "Adam Sindelar <adamsh@google.com>"


def EulersDecimals():
    """Yields decimals of Euler's number, using continued fractions.

    This is used to generate random looking, but deterministic series of digits
    for testing purposes. Unlike PRNGs, the output is always guaranteed to be
    the same and is implementation-independent.

    For explanation of how this works see (for example) here:
    http://mathworld.wolfram.com/eContinuedFraction.html
    """

    def e_continued_fraction():
        """Continued fraction for Euler's.

        This is the series 1, 0, 1, 1, 2, 1, 1, 4...
        """
        yield 1
        k = 0
        while True:
            yield k
            k += 2
            yield 1
            yield 1

    def yield_digits(p, q):
        while p > 0:
            if p > q:
                d = p // q
                p = p - q * d
            else:
                d = (10 * p) // q
                p = 10 * p - q * d

            yield d

    def z(fraction, a=1, b=0, c=0, d=1):
        for x in fraction:
            while a > 0 and b > 0 and c > 0 and d > 0:
                # Lowest and highest possible value of the next digit -
                # we yield the digit once they're equivalent.
                t = a // c
                t_ = b // d
                if t != t_:
                    break

                yield t
                a = (10 * (a - c * t))
                b = (10 * (b - d * t))
            a, b = x * a + b, a
            c, d = x * c + d, c

        for digit in yield_digits(a, c):
            yield digit

    return z(e_continued_fraction())
