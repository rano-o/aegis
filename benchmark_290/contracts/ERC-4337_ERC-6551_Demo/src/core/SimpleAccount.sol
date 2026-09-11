// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import "../interfaces/IAccount.sol";
import "../interfaces/IEntryPoint.sol";
import "../interfaces/UserOperation.sol";

/**
 * @title SimpleAccount
 * @notice Minimal smart contract wallet - FIXED VERSION
 */
contract SimpleAccount is IAccount {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // State variables
    address public owner;
    IEntryPoint private immutable _entryPoint;
    uint256 private _nonce;

    // Events
    event AccountInitialized(
        IEntryPoint indexed entryPoint,
        address indexed owner
    );
    event Executed(address indexed target, uint256 value, bytes data);

    // Modifiers
    modifier onlyOwnerOrEntryPoint() {
        require(
            msg.sender == owner || msg.sender == address(_entryPoint),
            "Not authorized"
        );
        _;
    }

    /**
     * @notice Constructor
     */
    constructor(IEntryPoint entryPoint_, address owner_) {
        _entryPoint = entryPoint_;
        owner = owner_;
        emit AccountInitialized(entryPoint_, owner_);
    }

    /**
     * @notice Validate user operation
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        // Only EntryPoint can call
        require(msg.sender == address(_entryPoint), "Not from EntryPoint");

        // Validate nonce
        require(userOp.nonce == _nonce, "Invalid nonce");
        _nonce++;

        // Validate signature
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        address signer = hash.recover(userOp.signature);

        if (signer != owner) {
            return 1; // SIG_VALIDATION_FAILED
        }

        // ✅ FIX: Only pay if actually requested AND we have funds
        // In our simplified model, EntryPoint uses deposit system
        // so missingAccountFunds should be 0
        if (missingAccountFunds > 0) {
            // Only pay if we have enough balance
            if (address(this).balance >= missingAccountFunds) {
                (bool success, ) = payable(msg.sender).call{
                    value: missingAccountFunds,
                    gas: type(uint256).max
                }("");
                // Don't revert if payment fails - EntryPoint will handle it
                (success); // silence unused variable warning
            }
        }

        return 0; // Success
    }

    /**
     * @notice Execute transaction
     */
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external onlyOwnerOrEntryPoint {
        (bool success, bytes memory result) = target.call{value: value}(data);

        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }

        emit Executed(target, value, data);
    }

    /**
     * @notice Batch execute multiple transactions
     */
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external onlyOwnerOrEntryPoint {
        require(
            targets.length == values.length && values.length == datas.length,
            "Length mismatch"
        );

        for (uint256 i = 0; i < targets.length; i++) {
            (bool success, bytes memory result) = targets[i].call{
                value: values[i]
            }(datas[i]);

            if (!success) {
                assembly {
                    revert(add(result, 32), mload(result))
                }
            }

            emit Executed(targets[i], values[i], datas[i]);
        }
    }

    /**
     * @notice Get current nonce
     */
    function getNonce() external view returns (uint256) {
        return _nonce;
    }

    /**
     * @notice Get EntryPoint address
     */
    function entryPoint() external view returns (address) {
        return address(_entryPoint);
    }

    /**
     * @notice Deposit to EntryPoint
     */
    function addDeposit() external payable {
        _entryPoint.depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Get deposit at EntryPoint
     */
    function getDeposit() external view returns (uint256) {
        return _entryPoint.balanceOf(address(this));
    }

    // Receive ETH
    receive() external payable {}
}
