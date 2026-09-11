// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IValidator} from "../../interfaces/IValidator.sol";

/// @title ECDSAValidator - Validates owner ECDSA signatures for AgentWallet
/// @notice Installed as a validator module. Stores the owner per wallet.
/// @dev ERC-165 supportsInterface is intentionally omitted. Modules are trusted,
/// audited code installed by the wallet owner, so on-chain interface discovery
/// adds gas overhead without meaningful security benefit.
///
/// ECDSA Malleability: This contract uses OpenZeppelin ECDSA v5.2.0 which includes
/// built-in s-value malleability protection (rejects s > secp256k1n/2) in tryRecover().
/// No additional malleability checks are needed.
contract ECDSAValidator is IValidator {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    mapping(address wallet => address owner) public walletOwner;

    uint256 constant VALIDATION_SUCCESS = 0;
    uint256 constant VALIDATION_FAILED = 1;

    bytes4 constant ERC1271_SUCCESS = 0x1626ba7e;

    event OwnerSet(address indexed wallet, address indexed owner);
    event OwnerRemoved(address indexed wallet);

    error AlreadyInitialized();
    error NotInitialized();
    error InvalidOwner();

    /// @notice Called when module is installed on a wallet
    function onInstall(bytes calldata data) external {
        address owner = abi.decode(data, (address));
        if (owner == address(0)) revert InvalidOwner();
        if (walletOwner[msg.sender] != address(0)) revert AlreadyInitialized();
        walletOwner[msg.sender] = owner;
        emit OwnerSet(msg.sender, owner);
    }

    /// @notice Called when module is uninstalled
    function onUninstall() external {
        delete walletOwner[msg.sender];
        emit OwnerRemoved(msg.sender);
    }

    /// @notice Update the owner for a wallet (called by wallet on ownership transfer)
    function updateOwner(address newOwner) external {
        if (walletOwner[msg.sender] == address(0)) revert NotInitialized();
        if (newOwner == address(0)) revert InvalidOwner();
        walletOwner[msg.sender] = newOwner;
        emit OwnerSet(msg.sender, newOwner);
    }

    /// @notice Validate a UserOp signature
    /// @dev Called by AgentWallet.validateUserOp via .call()
    /// @dev Uses tryRecover to return VALIDATION_FAILED instead of reverting on malformed signatures (ERC-4337 best practice)
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view returns (uint256) {
        address owner = walletOwner[userOp.sender];
        if (owner == address(0)) return VALIDATION_FAILED;

        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(ethHash, userOp.signature);

        if (err != ECDSA.RecoverError.NoError) return VALIDATION_FAILED;
        if (recovered == owner) return VALIDATION_SUCCESS;
        return VALIDATION_FAILED;
    }

    /// @notice ERC-1271 signature validation
    /// @dev Tries raw hash first (EIP-712 typed data), then falls back to personal_sign
    /// prefix. This ensures compatibility with both eth_signTypedData_v4 (raw hash)
    /// and eth_sign/personal_sign (prefixed hash) signing flows.
    function isValidSignature(
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4) {
        address owner = walletOwner[msg.sender];
        if (owner == address(0)) return bytes4(0xffffffff);

        // Try raw hash first (EIP-712 typed data / eth_signTypedData_v4)
        (address recovered, ECDSA.RecoverError err,) = ECDSA.tryRecover(hash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) return ERC1271_SUCCESS;

        // Fallback: try with personal_sign prefix (eth_sign / personal_sign)
        bytes32 ethHash = hash.toEthSignedMessageHash();
        (recovered, err,) = ECDSA.tryRecover(ethHash, signature);
        if (err == ECDSA.RecoverError.NoError && recovered == owner) return ERC1271_SUCCESS;

        return bytes4(0xffffffff);
    }

    /// @notice Get owner for a wallet
    function getOwner(address wallet) external view returns (address) {
        return walletOwner[wallet];
    }
}
