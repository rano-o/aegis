// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IEntryPoint } from "./IEntryPoint.sol";

/**
 * @title IModule
 * @notice Base interface for all account modules
 * @dev Modules extend account functionality (validation, execution, hooks)
 */
interface IModule {
    /**
     * @notice Module type enumeration
     * @param Validator Validates signatures and permissions
     * @param Executor Executes actions on behalf of account
     * @param Hook Pre/post execution hooks
     * @param Fallback Handles unknown function calls
     */
    enum ModuleType {
        Validator,
        Executor,
        Hook,
        Fallback
    }

    /**
     * @notice Called when module is installed on an account
     * @param data Initialization data
     */
    function onInstall(bytes calldata data) external;

    /**
     * @notice Called when module is uninstalled from an account
     * @param data Cleanup data
     */
    function onUninstall(bytes calldata data) external;

    /**
     * @notice Check if module is of a specific type
     * @param moduleType The type to check
     * @return True if module is of the specified type
     */
    function isModuleType(ModuleType moduleType) external view returns (bool);

    /**
     * @notice Get the module type(s)
     * @return Bitmap of supported module types
     */
    function moduleTypes() external view returns (uint256);
}

/**
 * @title IValidator
 * @notice Validator module interface - validates UserOperation signatures
 * @dev Validators can implement various signature schemes:
 *      - ECDSA (EOA-style)
 *      - Multisig (M-of-N)
 *      - Passkeys (WebAuthn)
 *      - Session keys (delegated signing)
 */
interface IValidator is IModule {
    /**
     * @notice Validate a UserOperation signature
     * @dev Returns validation data in ERC-4337 format:
     *      - 0 = valid signature
     *      - 1 = invalid signature
     *      - Other values encode validUntil/validAfter
     *
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @return validationData Packed validation result
     */
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData);

    /**
     * @notice Validate an EIP-1271 signature
     * @param hash The hash that was signed
     * @param signature The signature to validate
     * @return magicValue EIP-1271 magic value if valid
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4 magicValue);
}

/**
 * @title IExecutor
 * @notice Executor module interface - executes actions on behalf of the account
 * @dev Executors can:
 *      - Perform automated actions (DCA, limit orders)
 *      - Execute recovery procedures
 *      - Manage account state
 */
interface IExecutor is IModule {
    // Executors call back into the account using IAccountExecute
}

/**
 * @title IHook
 * @notice Hook module interface - pre/post execution hooks
 * @dev Hooks can:
 *      - Enforce spending limits
 *      - Require additional approvals for large transactions
 *      - Log/audit transactions
 */
interface IHook is IModule {
    /**
     * @notice Called before execution
     * @param target Call target
     * @param value ETH value
     * @param data Call data
     * @return hookData Data to pass to postHook
     */
    function preHook(address target, uint256 value, bytes calldata data) external returns (bytes memory hookData);

    /**
     * @notice Called after execution
     * @param hookData Data from preHook
     * @param success Whether execution succeeded
     * @param returnData Return data from execution
     */
    function postHook(bytes calldata hookData, bool success, bytes calldata returnData) external;
}

/**
 * @title IFallback
 * @notice Fallback module interface - handles unknown function calls
 * @dev Used for:
 *      - Token callbacks (onERC721Received, etc.)
 *      - Custom functionality extensions
 */
interface IFallback is IModule {
    // Fallback modules are called via delegatecall when selector doesn't match
}
