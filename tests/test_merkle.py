"""Exhaustive checks of the RFC 6962 tree: every inclusion and consistency
proof for small trees verifies, and every tampering is rejected."""

from __future__ import annotations

import hashlib

import pytest

from translog.merkle import (
    EMPTY_ROOT,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    node_hash,
    root_hash,
    verify_consistency,
    verify_inclusion,
)

N = 33


def leaves(n: int) -> list[bytes]:
    return [leaf_hash(f"cert-{i}".encode()) for i in range(n)]


def test_domain_separation() -> None:
    assert leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    assert node_hash(b"a", b"b") == hashlib.sha256(b"\x01ab").digest()
    assert root_hash([]) == EMPTY_ROOT


def test_small_trees_by_hand() -> None:
    a, b, c = leaves(3)
    assert root_hash([a]) == a
    assert root_hash([a, b]) == node_hash(a, b)
    assert root_hash([a, b, c]) == node_hash(node_hash(a, b), c)


def test_all_inclusion_proofs_verify() -> None:
    for n in range(1, N):
        hs = leaves(n)
        root = root_hash(hs)
        for i in range(n):
            assert verify_inclusion(i, n, hs[i], inclusion_proof(i, hs), root), (i, n)


def test_all_consistency_proofs_verify() -> None:
    hs = leaves(N)
    for n in range(1, N):
        for m in range(1, n + 1):
            proof = consistency_proof(m, hs[:n])
            assert verify_consistency(m, n, root_hash(hs[:m]), root_hash(hs[:n]), proof), (m, n)


@pytest.mark.parametrize("n", [2, 5, 8, 13])
def test_inclusion_rejects_tampering(n: int) -> None:
    hs = leaves(n)
    root = root_hash(hs)
    i = n // 2
    proof = inclusion_proof(i, hs)
    other = leaf_hash(b"forged")
    assert not verify_inclusion(i, n, other, proof, root)  # wrong leaf
    assert not verify_inclusion((i + 1) % n, n, hs[i], proof, root)  # wrong index
    # (A wrong tree_size with the right root can still verify for some indices;
    # that's fine because the signed tree head binds root and size together.)
    assert not verify_inclusion(i, n, hs[i], proof, other)  # wrong root
    assert not verify_inclusion(i, n, hs[i], proof[:-1], root)  # truncated
    assert not verify_inclusion(i, n, hs[i], [*proof, other], root)  # extended
    bad = list(proof)
    bad[0] = other
    assert not verify_inclusion(i, n, hs[i], bad, root)  # altered node
    assert not verify_inclusion(n, n, hs[i], proof, root)  # index out of range


@pytest.mark.parametrize(("m", "n"), [(1, 2), (3, 7), (4, 8), (5, 13), (6, 6)])
def test_consistency_rejects_fork(m: int, n: int) -> None:
    hs = leaves(n)
    proof = consistency_proof(m, hs)
    old, new = root_hash(hs[:m]), root_hash(hs)
    forked = list(hs)
    forked[0] = leaf_hash(b"rewritten history")
    assert not verify_consistency(m, n, root_hash(forked[:m]), new, proof)
    assert not verify_consistency(m, n, old, root_hash(forked), proof) or m == n and not proof
    if proof:
        bad = list(proof)
        bad[-1] = leaf_hash(b"x")
        assert not verify_consistency(m, n, old, new, bad)


def test_consistency_shrinking_tree_rejected() -> None:
    hs = leaves(8)
    assert not verify_consistency(8, 4, root_hash(hs), root_hash(hs[:4]), [])


def test_consistency_empty_proof_for_growth_rejected() -> None:
    hs = leaves(8)
    assert not verify_consistency(4, 8, root_hash(hs[:4]), root_hash(hs), [])


def test_proof_index_errors() -> None:
    with pytest.raises(ValueError):
        inclusion_proof(3, leaves(3))
    with pytest.raises(ValueError):
        consistency_proof(0, leaves(3))
