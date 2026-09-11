// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IAccount06} from "lib/account-abstraction/contracts/legacy/v06/IAccount06.sol";
import {UserOperation06} from "lib/account-abstraction/contracts/legacy/v06/UserOperation06.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/legacy/v06/IEntryPoint06.sol";

contract ERC4337 is IAccount06, Ownable {
    ////////////
    // Errors //
    ///////////
    error ERC4337__NotFromEntryPoint();
    error ERC4337__NotFromEntryPointOrOwner();
    error ERC4337__CallFailed(bytes);

    /////////////////////
    // State Variables //
    ////////////////////
    IEntryPoint private immutable i_entryPoint;

    ///////////////
    // Modifiers //
    //////////////
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert ERC4337__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert ERC4337__NotFromEntryPointOrOwner();
        }
        _;
    }

    ///////////////
    // functions //
    //////////////
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    receive() external payable {}

    ////////////////////////
    // External Functions //
    ///////////////////////
    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner {
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if (!success) {
            revert ERC4337__CallFailed(result);
        }
    }

    // entrypoint -> this contract
    function validateUserOp(UserOperation06 calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        requireFromEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        // _validateNonce()
        _payPrefund(missingAccountFunds);
    }

    ////////////////////////
    // Internal Functions //
    ///////////////////////

    //EIP-191 version of the signed hash
    function _validateSignature(UserOperation06 calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            (success);
        }
    }

    /////////////
    // Getters //
    ////////////
    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
