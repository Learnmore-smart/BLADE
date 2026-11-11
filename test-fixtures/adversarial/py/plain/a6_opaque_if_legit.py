GUARD = 0x5150


def check_invariant():
    # Same number-theoretic shape BLA uses; here it guards a real invariant.
    if (((7 * ((GUARD | 5) ** 2) - 1) & 0xFFFFFFFF) == (((GUARD ^ 8) ** 2) & 0xFFFFFFFF) and ((GUARD * (GUARD + 1)) & 1) == 1):
        print("invariant violated")
        return True
    return False
