// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title HazMat register anchor
/// @notice Publishes one merkle root per epoch so a sheet can be checked on-chain.
///         Rules are frozen in matcher/hazmat/anchor.py: leaf is keccak256 of the
///         canonical placard json, every pair is sorted before hashing, and an odd
///         level duplicates its last node. Consequently a proof carries no side
///         flags, and folding it is the same operation the prover performed.
contract HazMatAnchor {
    /// @notice epoch => root, first writer wins so a published root cannot be rewritten
    mapping(uint256 => bytes32) public roots;
    mapping(uint256 => string) public registerDigests;

    event Anchored(uint256 indexed epoch, bytes32 root, string registerDigest);

    error AlreadyAnchored(uint256 epoch);
    error EmptyRoot();

    /// @notice Publish the root for an epoch. Anyone may call it; the first call for
    ///         an epoch is final, which is what makes the anchor worth citing.
    function anchor(uint256 epoch, bytes32 root, string calldata registerDigest) external {
        if (root == bytes32(0)) revert EmptyRoot();
        if (roots[epoch] != bytes32(0)) revert AlreadyAnchored(epoch);
        roots[epoch] = root;
        registerDigests[epoch] = registerDigest;
        emit Anchored(epoch, root, registerDigest);
    }

    /// @notice Recompute a root from a leaf and its siblings. Sorted pairs, so the
    ///         order of the proof is the only thing that matters, not a side flag.
    function fold(bytes32 leaf, bytes32[] calldata proof) public pure returns (bytes32 node) {
        node = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            node = node <= proof[i]
                ? keccak256(abi.encodePacked(node, proof[i]))
                : keccak256(abi.encodePacked(proof[i], node));
        }
    }

    /// @notice True when the leaf belongs to the published root for that epoch.
    function verify(bytes32 leaf, bytes32[] calldata proof, uint256 epoch) external view returns (bool) {
        bytes32 root = roots[epoch];
        if (root == bytes32(0)) return false;
        return fold(leaf, proof) == root;
    }
}
