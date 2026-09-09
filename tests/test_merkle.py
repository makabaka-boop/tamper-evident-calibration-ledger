from __future__ import annotations

import pytest

from ledger.merkle import (
    InclusionStep,
    consistency_proof,
    inclusion_proof,
    leaf_hash,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)


@pytest.mark.parametrize("size", range(1, 18))
def test_every_leaf_has_valid_proof_at_odd_and_even_boundaries(size: int) -> None:
    leaves = [leaf_hash(f"event-{index}".encode()) for index in range(size)]
    root = merkle_root(leaves)
    for index, leaf in enumerate(leaves):
        proof = inclusion_proof(leaves, index)
        assert verify_inclusion(leaf, index, size, proof, root)


@pytest.mark.parametrize("new_size", range(2, 18))
def test_every_prefix_has_valid_consistency_proof(new_size: int) -> None:
    leaves = [leaf_hash(f"event-{index}".encode()) for index in range(new_size)]
    for old_size in range(1, new_size):
        proof = consistency_proof(leaves, old_size)
        assert verify_consistency(
            old_size,
            new_size,
            merkle_root(leaves[:old_size]),
            merkle_root(leaves),
            proof,
        )


def test_tampering_order_and_deletion_fail_verification() -> None:
    leaves = [leaf_hash(item) for item in (b"a", b"b", b"c", b"d", b"e")]
    root = merkle_root(leaves)
    proof = inclusion_proof(leaves, 2)
    assert not verify_inclusion(leaf_hash(b"C"), 2, len(leaves), proof, root)
    swapped = [leaves[1], leaves[0], *leaves[2:]]
    deleted = [*leaves[:3], *leaves[4:]]
    assert merkle_root(swapped) != root
    assert merkle_root(deleted) != root


def test_modified_proof_hash_fails() -> None:
    leaves = [leaf_hash(str(index).encode()) for index in range(7)]
    proof = inclusion_proof(leaves, 3)
    proof[0] = InclusionStep(proof[0].side, b"\xff" * 32)
    assert not verify_inclusion(leaves[3], 3, 7, proof, merkle_root(leaves))


def test_index_and_tree_shape_are_cryptographically_bound() -> None:
    leaves = [leaf_hash(str(index).encode()) for index in range(5)]
    proof = inclusion_proof(leaves, 1)
    root = merkle_root(leaves)
    assert verify_inclusion(leaves[1], 1, 5, proof, root)
    assert not verify_inclusion(leaves[1], 0, 5, proof, root)
    assert not verify_inclusion(leaves[1], 1, 4, proof, root)
    assert not verify_inclusion(leaves[1], 1, 5, [*proof, proof[-1]], root)
