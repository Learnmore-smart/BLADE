"""Sample module exercising several function shapes."""

import os
import sys


def helper(x, y):
    """Add two values."""
    return x + y


class Worker:
    def run(self, items):
        total = 0
        for it in items:
            total += helper(it, 1)
        return total

    @staticmethod
    def normalize(name):
        return name.strip().lower()


async def fetch(url):
    return url


def outer():
    def inner():
        return sys.version
    return inner()


def leading_comment():
    # a leading comment before the first statement
    x = 1
    return x


def docstring_only():
    """Nothing but a docstring."""
