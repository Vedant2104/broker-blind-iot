"""RFC 6962 / RFC 9162 Merkle tree: tree hash, inclusion and consistency proofs,
and their verification. Pure functions over lists of leaf hashes."""

from __future__ import annotations

import hashlib

EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly less than n (n >= 2)."""
    return 1 << ((n - 1).bit_length() - 1)


def root_hash(hashes: list[bytes]) -> bytes:
    """MTH(D[n]) over leaf hashes."""
    n = len(hashes)
    if n == 0:
        return EMPTY_ROOT
    if n == 1:
        return hashes[0]
    k = _split(n)
    return node_hash(root_hash(hashes[:k]), root_hash(hashes[k:]))


def inclusion_proof(index: int, hashes: list[bytes]) -> list[bytes]:
    """PATH(m, D[n]): audit path for leaf ``index`` in the tree over ``hashes``."""
    n = len(hashes)
    if not 0 <= index < n:
        raise ValueError(f"leaf index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _split(n)
    if index < k:
        return inclusion_proof(index, hashes[:k]) + [root_hash(hashes[k:])]
    return inclusion_proof(index - k, hashes[k:]) + [root_hash(hashes[:k])]


def consistency_proof(first: int, hashes: list[bytes]) -> list[bytes]:
    """PROOF(m, D[n]): proves the tree of size ``first`` is a prefix of this tree."""
    n = len(hashes)
    if not 0 < first <= n:
        raise ValueError(f"first size {first} out of range for tree size {n}")
    return _subproof(first, hashes, True)


def _subproof(m: int, hashes: list[bytes], complete: bool) -> list[bytes]:
    n = len(hashes)
    if m == n:
        return [] if complete else [root_hash(hashes)]
    k = _split(n)
    if m <= k:
        return _subproof(m, hashes[:k], complete) + [root_hash(hashes[k:])]
    return _subproof(m - k, hashes[k:], False) + [root_hash(hashes[:k])]


def verify_inclusion(
    index: int, tree_size: int, leaf: bytes, proof: list[bytes], root: bytes
) -> bool:
    """RFC 9162 §2.1.3.2. ``leaf`` is the leaf *hash*."""
    if index >= tree_size or index < 0:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, proof: list[bytes]
) -> bool:
    """RFC 9162 §2.1.4.2."""
    if first < 0 or second < first:
        return False
    if first == second:
        return not proof and first_root == second_root
    if first == 0:
        return not proof  # the empty tree is a prefix of every tree
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
