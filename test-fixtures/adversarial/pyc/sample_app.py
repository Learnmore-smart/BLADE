"""Sample app for PYC adversarial testing."""

import os
import sys

CONSTANT = 42
NAMES = ["alpha", "beta", "gamma"]


def helper_one(x, y):
    """First helper."""
    total = x + y
    return total * 2


def helper_two(a, b=10, *args, key=None, **kwargs):
    """Second helper with varied args."""
    result = a * b
    for item in args:
        result += len(str(item))
    if key:
        result -= len(key)
    for v in kwargs.values():
        result += hash(v) % 7
    return result


class Greeter:
    def __init__(self, name):
        self.name = name

    def greet(self):
        def inner():
            return f"hello {self.name}"

        return inner()


def main():
    g = Greeter("world")
    print(g.greet(), helper_one(1, 2), helper_two(3, key="k", extra=1))


if __name__ == "__main__":
    main()
