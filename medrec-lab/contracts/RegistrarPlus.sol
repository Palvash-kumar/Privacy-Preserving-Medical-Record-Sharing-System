// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Summary.sol";

/**
 * @title RegistrarPlus (MedRec+ Privacy-Preserving Registrar)
 * @notice Implements E2.2: Eliminates identifying plaintext strings on-chain.
 *         Participants register their pairwise pseudonymous addresses and
 *         publish their X25519 public keys for secure key wrapping.
 */
contract RegistrarPlus {
    mapping(address => address) public summaryOf;
    mapping(address => bytes) public x25519PublicKeyOf;
    address[] private _registeredAddresses;

    event Registered(address indexed who, address summary, bytes x25519PublicKey);

    error AlreadyRegistered();

    function register(bytes calldata x25519PublicKey) external {
        if (summaryOf[msg.sender] != address(0)) revert AlreadyRegistered();

        Summary s = new Summary(msg.sender);
        summaryOf[msg.sender] = address(s);
        x25519PublicKeyOf[msg.sender] = x25519PublicKey;
        _registeredAddresses.push(msg.sender);

        emit Registered(msg.sender, address(s), x25519PublicKey);
    }

    function getSummary(address who) external view returns (address) {
        return summaryOf[who];
    }

    function getPublicKey(address who) external view returns (bytes memory) {
        return x25519PublicKeyOf[who];
    }

    function totalRegistered() external view returns (uint256) {
        return _registeredAddresses.length;
    }
}
