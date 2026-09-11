// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {
    PackedUserOperation
} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";

import {SessionKeyManager} from "./SessionKeyManager.sol";
import {SignatureUtils} from "../utils/SignatureUtils.sol";

/**
 * @title SmartAccount
 * @author NEXTECHARHITECT
 * @notice ERC-4337 Smart Account with session keys
 */
contract SmartAccount is IAccount, SessionKeyManager {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    error NotEntryPoint();
    error NotOwner();
    error ExecutionFailed();

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/
    address public immutable entryPoint;
    address public owner;
    uint256 public nonce;

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/
    modifier onlyEntryPoint() {
        if (msg.sender != entryPoint) revert NotEntryPoint();
        _;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/
    constructor(address _owner, address _entryPoint) {
        owner = _owner;
        entryPoint = _entryPoint;
    }

    /*//////////////////////////////////////////////////////////////
                        ERC-4337 VALIDATION
    //////////////////////////////////////////////////////////////*/
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingFunds
    ) external override onlyEntryPoint returns (uint256 validationData) {
        // nonce check
        if (userOp.nonce != nonce) {
            return _packValidationData(true, 0, 0);
        }

        unchecked {
            nonce++;
        }

        // recover signer
        address signer = SignatureUtils.recoverSigner(
            userOpHash,
            userOp.signature
        );

        bool authorized = signer == owner || _isValidSessionKey(signer);

        if (!authorized) {
            return _packValidationData(true, 0, 0);
        }

        // gas repayment
        if (missingFunds != 0) {
            (bool success, ) = payable(msg.sender).call{value: missingFunds}(
                ""
            );
            success;
        }

        return _packValidationData(false, 0, 0);
    }

    /*//////////////////////////////////////////////////////////////
                            EXECUTION
    //////////////////////////////////////////////////////////////*/
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyEntryPoint {
        (bool success, ) = target.call{value: value}(data);

        if (!success) revert ExecutionFailed();
    }

    /*//////////////////////////////////////////////////////////////
                    SESSION KEY OWNER FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    function enableSessionKey(address key, uint48 duration) external onlyOwner {
        _enableSessionKey(key, duration);
    }

    function disableSessionKey(address key) external onlyOwner {
        _disableSessionKey(key);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL HELPERS
    //////////////////////////////////////////////////////////////*/
    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (uint256 validationData) {
        assembly {
            validationData := or(
                sigFailed,
                or(shl(1, validUntil), shl(49, validAfter))
            )
        }
    }

    receive() external payable {}
}
