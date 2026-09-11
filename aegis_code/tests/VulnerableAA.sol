// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VulnerableAA {
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes callData;
        bytes paymasterAndData;
        bytes signature;
    }

    function validateUserOp(UserOperation calldata, bytes32, uint256) external pure returns (uint256) {
        // intentionally vulnerable: missing signature + nonce checks
        return 0;
    }

    function getUserOpHash(UserOperation calldata op) public pure returns (bytes32) {
        // intentionally weak: encodePacked + missing domain binding
        return keccak256(abi.encodePacked(op.sender, op.callData));
    }
}

contract VulnerablePaymaster {
    struct UserOperation {
        address sender;
        uint256 nonce;
        bytes callData;
        bytes paymasterAndData;
        bytes signature;
    }

    function validatePaymasterUserOp(UserOperation calldata, bytes32, uint256)
        external
        pure
        returns (bytes memory context, uint256 validationData)
    {
        // intentionally vulnerable: no policy checks/replay checks
        return ("", 0);
    }

    function postOp(uint8, bytes calldata, uint256) external pure {
        // intentionally vulnerable: no accounting logic
    }
}
