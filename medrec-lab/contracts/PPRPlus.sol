// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Summary.sol";

/**
 * @title PPRPlus (MedRec+ Enhanced Patient–Provider Relationship)
 * @notice Implements MedRec+ privacy and security improvements:
 *         - E1: Per-viewer wrapped keys (event-based vs storage-based publishing)
 *         - E2: Hidden selectors via salted cryptographic commitments
 *         - E3: Time-bound grants with expiry timestamps and explicit revocation
 *         - E4: Break-glass emergency access role with auto-expiry and audit logging
 */
contract PPRPlus {
    address public patient;
    address public provider;
    string  public dbHost;

    struct Pointer {
        bytes32 selectorCommit; // keccak256(selector || salt)
        bytes32 dataHash;       // SHA-256 of the ciphertext blob
        uint64  createdAt;
    }

    struct Grant {
        address viewer;
        bytes32 selectorCommit;
        uint64  expiresAt;
        bool    revoked;
        bool    exists;
    }

    Pointer[] public pointers;

    // viewer => selectorCommit => Grant
    mapping(address => mapping(bytes32 => Grant)) public grants;

    // Optional on-chain storage for wrapped keys (for B1/H4 gas comparison against events)
    mapping(address => mapping(bytes32 => bytes)) public wrappedKeyStorage;

    // Viewers list for enumeration
    address[] private _viewers;
    mapping(address => bool) private _isViewer;

    // Emergency Access (E4)
    address public emergencyRole;
    uint64  public emergencyExpiresAt;
    mapping(bytes32 => bool) public emergencySelectors;

    event PointerAdded(address indexed ppr, uint256 index, bytes32 indexed selectorCommit, bytes32 dataHash);
    event Shared(address indexed ppr, address indexed viewer, bytes32 indexed selectorCommit, uint64 expiresAt);
    event KeyWrapped(address indexed ppr, address indexed viewer, bytes32 indexed selectorCommit, bytes wrappedKey);
    event Revoked(address indexed ppr, address indexed viewer, bytes32 indexed selectorCommit);
    event EmergencyRoleSet(address indexed ppr, address indexed emergencyRole);
    event EmergencySelectorSet(address indexed ppr, bytes32 indexed selectorCommit, bool allowed);
    event EmergencyAccess(address indexed ppr, address indexed caller, bytes32 reasonCode, uint64 expiresAt);
    event EmergencyRevoked(address indexed ppr);

    error NotProvider();
    error NotPatient();
    error NotEmergencyRole();
    error GrantExpired();
    error GrantRevoked();
    error InvalidDuration();
    error SelectorNotFound();

    modifier onlyProvider() {
        if (msg.sender != provider) revert NotProvider();
        _;
    }

    modifier onlyPatient() {
        if (msg.sender != patient) revert NotPatient();
        _;
    }

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

        if (patientSummary != address(0)) {
            Summary(patientSummary).addRelationship(address(this));
        }
        if (providerSummary != address(0)) {
            Summary(providerSummary).addRelationship(address(this));
        }
    }

    // ── Pointer Management ───────────────────────────────────────────────────

    function addPointer(bytes32 selectorCommit, bytes32 dataHash) external onlyProvider {
        uint256 idx = pointers.length;
        pointers.push(Pointer({
            selectorCommit: selectorCommit,
            dataHash: dataHash,
            createdAt: uint64(block.timestamp)
        }));
        emit PointerAdded(address(this), idx, selectorCommit, dataHash);
    }

    // ── Sharing & Grants (E1 & E3) ──────────────────────────────────────────

    /**
     * @notice Share access with a viewer using event-based wrapped key publishing (gas-efficient).
     */
    function share(
        address viewer,
        bytes32 selectorCommit,
        uint64 expiresAt,
        bytes calldata wrappedKey
    ) external onlyPatient {
        _setGrant(viewer, selectorCommit, expiresAt);
        emit KeyWrapped(address(this), viewer, selectorCommit, wrappedKey);
    }

    /**
     * @notice Share access with a viewer storing the wrapped key in contract storage (for H4 comparison).
     */
    function shareWithStorage(
        address viewer,
        bytes32 selectorCommit,
        uint64 expiresAt,
        bytes calldata wrappedKey
    ) external onlyPatient {
        _setGrant(viewer, selectorCommit, expiresAt);
        wrappedKeyStorage[viewer][selectorCommit] = wrappedKey;
        emit KeyWrapped(address(this), viewer, selectorCommit, wrappedKey);
    }

    function _setGrant(address viewer, bytes32 selectorCommit, uint64 expiresAt) internal {
        grants[viewer][selectorCommit] = Grant({
            viewer: viewer,
            selectorCommit: selectorCommit,
            expiresAt: expiresAt,
            revoked: false,
            exists: true
        });

        if (!_isViewer[viewer]) {
            _viewers.push(viewer);
            _isViewer[viewer] = true;
        }

        emit Shared(address(this), viewer, selectorCommit, expiresAt);
    }

    function revoke(address viewer, bytes32 selectorCommit) external onlyPatient {
        Grant storage g = grants[viewer][selectorCommit];
        g.revoked = true;
        emit Revoked(address(this), viewer, selectorCommit);
    }

    // ── Emergency Access (E4) ────────────────────────────────────────────────

    function setEmergencyRole(address _role) external onlyPatient {
        emergencyRole = _role;
        emit EmergencyRoleSet(address(this), _role);
    }

    function setEmergencySelector(bytes32 selectorCommit, bool allowed) external onlyPatient {
        emergencySelectors[selectorCommit] = allowed;
        emit EmergencySelectorSet(address(this), selectorCommit, allowed);
    }

    function emergencyAccess(bytes32 reasonCode, uint64 duration) external {
        if (msg.sender != emergencyRole || emergencyRole == address(0)) revert NotEmergencyRole();
        if (duration == 0 || duration > 86400) revert InvalidDuration(); // max 24 hours

        emergencyExpiresAt = uint64(block.timestamp + duration);
        emit EmergencyAccess(address(this), msg.sender, reasonCode, emergencyExpiresAt);
    }

    function revokeEmergency() external onlyPatient {
        emergencyExpiresAt = 0;
        emit EmergencyRevoked(address(this));
    }

    // ── Permission Verification ──────────────────────────────────────────────

    function canView(address who, bytes32 selectorCommit) external view returns (bool) {
        // Patient and provider always have access
        if (who == patient || who == provider) return true;

        // Emergency role active grant check
        if (who == emergencyRole && emergencyRole != address(0)) {
            if (block.timestamp < emergencyExpiresAt && emergencySelectors[selectorCommit]) {
                return true;
            }
        }

        // Viewer grant check
        Grant memory g = grants[who][selectorCommit];
        if (!g.exists || g.revoked) return false;
        if (block.timestamp >= g.expiresAt) return false;

        return true;
    }

    // ── View Helpers ─────────────────────────────────────────────────────────

    function pointerCount() external view returns (uint256) {
        return pointers.length;
    }

    function getViewers() external view returns (address[] memory) {
        return _viewers;
    }

    function getGrant(address viewer, bytes32 selectorCommit) external view returns (Grant memory) {
        return grants[viewer][selectorCommit];
    }
}
