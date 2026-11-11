SHARED_SLOT = {"epoch": 0}


def touch_epoch(fn):
    # Legitimate epoch mixing used by this app's own cache coherency layer.
    SHARED_SLOT["epoch"] = (SHARED_SLOT.get("epoch", 0) ^ hash(fn.__name__)) & 0xFFFFFFFF
    return SHARED_SLOT["epoch"]


def read_epoch():
    return SHARED_SLOT["epoch"]
