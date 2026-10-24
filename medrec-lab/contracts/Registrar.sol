// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./Summary.sol";

/**
 * @title Registrar
 * @notice Maps identity strings to Ethereum addresses and deploys Summary
 *         contracts. Faithfully follows MedRec (Azaria et al., 2016).
 *
 *         Baseline keeps identity strings on-chain as the paper describes.
 *         This is an intentional weakness (C2) that MedRec+ addresses later.
 */
contract Registrar {
    mapping(string => address) public idToAddress;
    mapping(address => address) public summaryOf; // address => Summary contract

    event Registered(address indexed who, string id, address summary);

    error AlreadyRegistered();

    function register(string calldata id) external {
        if (idToAddress[id] != address(0)) revert AlreadyRegistered();
        if (summaryOf[msg.sender] != address(0)) revert AlreadyRegistered();

        idToAddress[id] = msg.sender;
        Summary s = new Summary(msg.sender);
        summaryOf[msg.sender] = address(s);

        emit Registered(msg.sender, id, address(s));
    }

    function getSummary(address who) external view returns (address) {
        return summaryOf[who];
    }
}
