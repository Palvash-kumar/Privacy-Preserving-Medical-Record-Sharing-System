// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Summary
 * @notice Per-participant index of relationships (PPR contracts) with status
 *         tracking. Each patient/provider/viewer gets one Summary via the
 *         Registrar. Status flow follows MedRec: New → PendingUpdate → Acknowledged.
 */
contract Summary {
    address public owner;

    enum Status { New, PendingUpdate, Acknowledged }

    struct Rel {
        address ppr;
        Status status;
    }

    Rel[] public rels;

    event RelationshipAdded(address indexed ppr, uint256 index);
    event StatusChanged(uint256 indexed index, Status newStatus);

    error NotOwner();
    error NotOwnerOrPPR();
    error InvalidIndex();

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    constructor(address _owner) {
        owner = _owner;
    }

    /// @notice Called by a PPR contract (or its creator) to register a relationship.
    function addRelationship(address ppr) external {
        uint256 idx = rels.length;
        rels.push(Rel({ ppr: ppr, status: Status.New }));
        emit RelationshipAdded(ppr, idx);
    }

    /// @notice Owner or the PPR itself can advance status.
    function setStatus(uint256 idx, Status s) external {
        if (idx >= rels.length) revert InvalidIndex();
        // Allow owner or the PPR contract itself to update
        if (msg.sender != owner && msg.sender != rels[idx].ppr) revert NotOwnerOrPPR();
        rels[idx].status = s;
        emit StatusChanged(idx, s);
    }

    function relCount() external view returns (uint256) {
        return rels.length;
    }
}
