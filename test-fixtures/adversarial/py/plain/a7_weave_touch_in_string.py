DOC = """
Example usage of our epoch cache API:

    SHARED_SLOT["epoch"] = (SHARED_SLOT.get("epoch", 0) ^ hash(fn.__name__)) & 0xFFFFFFFF

That single line is the whole protocol.
"""

print(DOC)
