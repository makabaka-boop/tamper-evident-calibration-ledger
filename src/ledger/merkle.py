from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

EMPTY_ROOT = hashlib.sha256(b"").digest()


class MerkleProofError(ValueError):
    """A requested Merkle proof cannot exist for the supplied tree boundary."""


def leaf_hash(data: bytes) -> bytes:
    """RFC 6962 domain-separated leaf hash."""

    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _split(size: int) -> int:
    if size < 2:
        raise ValueError("a Merkle subtree split requires at least two leaves")
    return 1 << ((size - 1).bit_length() - 1)


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """Compute the RFC 6962 Merkle tree hash without duplicating odd leaves."""

    size = len(leaves)
    if size == 0:
        return EMPTY_ROOT
    if size == 1:
        return leaves[0]
    k = _split(size)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


@dataclass(frozen=True)
class InclusionStep:
    side: Literal["left", "right"]
    hash: bytes


def inclusion_proof(leaves: Sequence[bytes], index: int) -> list[InclusionStep]:
    if not 0 <= index < len(leaves):
        raise MerkleProofError("leaf index is outside the tree")

    def walk(items: Sequence[bytes], local_index: int) -> list[InclusionStep]:
        if len(items) == 1:
            return []
        k = _split(len(items))
        if local_index < k:
            return walk(items[:k], local_index) + [InclusionStep("right", merkle_root(items[k:]))]
        return walk(items[k:], local_index - k) + [InclusionStep("left", merkle_root(items[:k]))]

    return walk(leaves, index)


def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    proof: Sequence[InclusionStep],
    expected_root: bytes,
) -> bool:
    if not 0 <= index < tree_size:
        return False
    expected_sides: list[str] = []

    def collect_sides(local_index: int, size: int) -> None:
        if size == 1:
            return
        k = _split(size)
        if local_index < k:
            collect_sides(local_index, k)
            expected_sides.append("right")
        else:
            collect_sides(local_index - k, size - k)
            expected_sides.append("left")

    collect_sides(index, tree_size)
    if len(proof) != len(expected_sides):
        return False
    current = leaf
    for step, expected_side in zip(proof, expected_sides, strict=True):
        if len(step.hash) != 32 or step.side != expected_side:
            return False
        current = (
            node_hash(step.hash, current) if step.side == "left" else node_hash(current, step.hash)
        )
    return current == expected_root


def consistency_proof(leaves: Sequence[bytes], old_size: int) -> list[bytes]:
    """Build an RFC 6962 consistency proof for old_size -> len(leaves)."""

    new_size = len(leaves)
    if old_size < 1 or old_size > new_size:
        raise MerkleProofError("old tree size must be between one and the new tree size")
    if old_size == new_size:
        return []

    def subproof(m: int, items: Sequence[bytes], complete: bool) -> list[bytes]:
        n = len(items)
        if m == n:
            return [] if complete else [merkle_root(items)]
        k = _split(n)
        if m <= k:
            return subproof(m, items[:k], complete) + [merkle_root(items[k:])]
        return subproof(m - k, items[k:], False) + [merkle_root(items[:k])]

    return subproof(old_size, leaves, True)


def verify_consistency(
    old_size: int,
    new_size: int,
    old_root: bytes,
    new_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """Verify an RFC 6962 consistency proof using roots and hashes only."""

    if old_size < 1 or old_size > new_size:
        return False
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if any(len(item) != 32 for item in proof):
        return False

    fn = old_size - 1
    sn = new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1

    offset = 0
    if fn == 0:
        old_hash = old_root
        new_hash = old_root
    else:
        if not proof:
            return False
        old_hash = proof[0]
        new_hash = proof[0]
        offset = 1

    for item in proof[offset:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            old_hash = node_hash(item, old_hash)
            new_hash = node_hash(item, new_hash)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            new_hash = node_hash(new_hash, item)
        fn >>= 1
        sn >>= 1

    return sn == 0 and old_hash == old_root and new_hash == new_root
