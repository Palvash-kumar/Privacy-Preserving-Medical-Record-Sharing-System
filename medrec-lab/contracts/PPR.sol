// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Summary.sol";

/**
 * @title PPR (Patient–Provider Relationship)
 * @notice Holds data pointers (selectors + hashes), the provider's gatekeeper
 *         address, and viewer permissions. Core of MedRec's access control.
 *
 *         Baseline: selectors and shares are stored in plaintext on-chain.
 *         This is intentional (weakness C2) and addressed in MedRec+.
 */
contract PPR {
    address public patient;
    address public provider;
    string  public dbHost; // "host:port" of the gatekeeper

    struct Pointer {
        string selector;   // e.g. "records:patient_id=1" or field-list selector
        bytes32 dataHash;  // SHA-256 of the off-chain data
    }

    Pointer[] public pointers;

    // viewer => array of permitted selectors
    mapping(address => string[]) private _shares;
    // viewer => selector => true  (for O(1) lookup)
    mapping(address => mapping(string => bool)) private _shareIndex;

    // Track all viewers for enumeration (needed for demos/benchmarks)
    address[] private _viewers;
    mapping(address => bool) private _isViewer;

    event PointerAdded(address indexed ppr, uint256 index, bytes32 dataHash);
    event Shared(address indexed ppr, address indexed viewer, string selector);
    event Revoked(address indexed ppr, address indexed viewer, string selector);

    error NotProvider();
    error NotPatient();
    error AlreadyShared();
    error NotShared();

    modifier onlyProvider() {
        if (msg.sender != provider) revert NotProvider();
        _;
    }

    modifier onlyPatient() {
        if (msg.sender != patient) revert NotPatient();
        _;
    }

    /**
     * @param _patient        Patient address
     * @param _provider       Provider address
     * @param _dbHost         Gatekeeper endpoint
     * @param patientSummary  Patient's Summary contract
     * @param providerSummary Provider's Summary contract
     */
    constructor(
        address _patient,
        address _provider,
        string memory _dbHost,
        address patientSummary,
        address providerSummary
    ) {
        patient = _patient;
        provider = _provider;
        dbHost = _dbHost;

        // Register this PPR in both summaries
        Summary(patientSummary).addRelationship(address(this));
        Summary(providerSummary).addRelationship(address(this));
    }

    /// @notice Provider adds a data pointer (selector + hash of the off-chain data).
    function addPointer(string calldata selector, bytes32 dataHash) external onlyProvider {
        uint256 idx = pointers.length;
        pointers.push(Pointer({ selector: selector, dataHash: dataHash }));
        emit PointerAdded(address(this), idx, dataHash);
    }

    /// @notice Patient grants a viewer access to a specific selector.
    function share(address viewer, string calldata selector) external onlyPatient {
        if (_shareIndex[viewer][selector]) revert AlreadyShared();

        _shares[viewer].push(selector);
        _shareIndex[viewer][selector] = true;

        if (!_isViewer[viewer]) {
            _viewers.push(viewer);
            _isViewer[viewer] = true;
        }

        emit Shared(address(this), viewer, selector);
    }

    /// @notice Patient revokes a viewer's access to a specific selector.
    function revoke(address viewer, string calldata selector) external onlyPatient {
        if (!_shareIndex[viewer][selector]) revert NotShared();

        _shareIndex[viewer][selector] = false;

        // Remove from the array
        string[] storage sels = _shares[viewer];
        for (uint256 i = 0; i < sels.length; i++) {
            if (keccak256(bytes(sels[i])) == keccak256(bytes(selector))) {
                sels[i] = sels[sels.length - 1];
                sels.pop();
                break;
            }
        }

        emit Revoked(address(this), viewer, selector);
    }

    /// @notice Check if `who` can view `selector`. Used by the gatekeeper.
    function canView(address who, string calldata selector) external view returns (bool) {
        // Patient and provider always have access
        if (who == patient || who == provider) return true;
        return _shareIndex[who][selector];
    }

    // --- View helpers ---

    function pointerCount() external view returns (uint256) {
        return pointers.length;
    }

    function getShares(address viewer) external view returns (string[] memory) {
        return _shares[viewer];
    }

    function getViewers() external view returns (address[] memory) {
        return _viewers;
    }
}
