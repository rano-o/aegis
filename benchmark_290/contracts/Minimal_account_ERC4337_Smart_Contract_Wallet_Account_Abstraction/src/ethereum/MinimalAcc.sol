//SPDX-License-Identifier: MIT

pragma solidity ^0.8.20;

import {IAccount} from "lib/account-abstraction/contracts/interfaces/IAccount.sol";
//Interface required for Account Abstraction

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {MessageHashUtils} from "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {SIG_VALIDATION_SUCCESS} from "lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

contract MinimalAccount is IAccount, Ownable{
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__CallFailed(bytes);

    IEntryPoint private immutable i_entryPoint;

    modifier requireEntryPoint() { 
        if(msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    modifier requireFromEntryPointOrOwner() {
        if(msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }
    // A sig is valid if it's the MinimalAccount owner

    receive() external payable {}

//------------------- FUNCTIONS -----------------------------// 

    function execute(address dest, uint256 value, bytes calldata functionData) external requireFromEntryPointOrOwner{
        (bool success, bytes memory result) = dest.call{value: value}(functionData);
        if(!success) {
            revert MinimalAccount__CallFailed(result);
        }
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        // can add sig here
        validationData = _validateSignature(userOp, userOpHash);
        // _validateNonce()
        _payPrefund(missingAccountFunds);
    }

    //EIP - 191 version of signed hash
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash) 
        internal 
        view 
        returns (uint256 validationData) 
    {
        // hash to Eth signed msg
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        // recover signer address 
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        // check signer == owner 
        if(signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }
    // how much ETH  this acc is missin to pay for gas?
    function _payPrefund(uint256 missingAccountFunds) internal {
        if(missingAccountFunds != 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds,gas: type(uint256).max}("");
            require(success, "Prefund fail");
            //msg.sender = entry point contract
        }
    } 
    
//-----------------GETTERS FUNCTIONS----------------------// 
 
    function getEntryPoint() public view returns (address) {
        return address(i_entryPoint);
    }
}