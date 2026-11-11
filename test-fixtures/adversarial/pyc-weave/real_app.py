"""Real application module for weave testing."""


def compute_license_fee(tier, seats):
    base = {"basic": 10, "pro": 25, "enterprise": 100}[tier]
    return base * seats


def validate_key(key):
    return len(key) == 32 and key.startswith("LIC-")


class LicenseStore:
    def __init__(self):
        self._cache = {}

    def get(self, name):
        return self._cache.get(name)

    def put(self, name, value):
        self._cache[name] = value
