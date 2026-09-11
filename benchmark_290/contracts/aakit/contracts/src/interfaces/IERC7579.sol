// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PackedUserOperation} from "./IERC4337.sol";

/**
 * @title IERC7579Account
 * @notice Interface for ERC-7579 modular smart accounts
 */
interface IERC7579Account {
    event ModuleInstalled(uint256 moduleTypeId, address module);
    event ModuleUninstalled(uint256 moduleTypeId, address module);

    /**
     * @notice Execute a transaction
     * @param mode Encoded execution mode
     * @param executionCalldata Encoded execution data
     */
    function execute(bytes32 mode, bytes calldata executionCalldata) external payable;

    /**
     * @notice Execute from an executor module
     * @param mode Encoded execution mode
     * @param executionCalldata Encoded execution data
     * @return returnData Array of return data from each call
     */
    function executeFromExecutor(
        bytes32 mode,
        bytes calldata executionCalldata
    ) external payable returns (bytes[] memory returnData);

    /**
     * @notice Install a module
     * @param moduleTypeId Type of module to install
     * @param module Address of the module
     * @param initData Initialization data for the module
     */
    function installModule(uint256 moduleTypeId, address module, bytes calldata initData) external payable;

    /**
     * @notice Uninstall a module
     * @param moduleTypeId Type of module to uninstall
     * @param module Address of the module
     * @param deInitData De-initialization data for the module
     */
    function uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData) external payable;

    /**
     * @notice Check if a module is installed
     * @param moduleTypeId Type of module
     * @param module Address of the module
     * @param additionalContext Additional context for the check
     * @return True if module is installed
     */
    function isModuleInstalled(
        uint256 moduleTypeId,
        address module,
        bytes calldata additionalContext
    ) external view returns (bool);

    /**
     * @notice Get account ID
     * @return accountId String identifier for the account implementation
     */
    function accountId() external view returns (string memory accountId);

    /**
     * @notice Check if execution mode is supported
     * @param encodedMode Encoded execution mode
     * @return True if mode is supported
     */
    function supportsExecutionMode(bytes32 encodedMode) external view returns (bool);

    /**
     * @notice Check if module type is supported
     * @param moduleTypeId Module type ID
     * @return True if module type is supported
     */
    function supportsModule(uint256 moduleTypeId) external view returns (bool);
}

/**
 * @title IERC7579Module
 * @notice Base interface for all ERC-7579 modules
 */
interface IERC7579Module {
    /**
     * @notice Initialize module
     * @param data Initialization data
     */
    function onInstall(bytes calldata data) external;

    /**
     * @notice De-initialize module
     * @param data De-initialization data
     */
    function onUninstall(bytes calldata data) external;

    /**
     * @notice Check if module is of a certain type
     * @param moduleTypeId Module type ID to check
     * @return True if module is of the specified type
     */
    function isModuleType(uint256 moduleTypeId) external view returns (bool);
}

/**
 * @title IERC7579Validator
 * @notice Interface for validator modules (type ID: 1)
 */
interface IERC7579Validator is IERC7579Module {
    /**
     * @notice Validate a user operation
     * @param userOp The user operation
     * @param userOpHash Hash of the user operation
     * @return validationData Packed validation data
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256 validationData);

    /**
     * @notice Validate a signature (ERC-1271)
     * @param sender Original sender of the signature request
     * @param hash Hash to validate
     * @param signature Signature bytes
     * @return Magic value if valid (0x1626ba7e)
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view returns (bytes4);
}

/**
 * @title IERC7579Executor  
 * @notice Interface for executor modules (type ID: 2)
 * @dev Executors don't have additional interface requirements beyond IERC7579Module
 */
interface IERC7579Executor is IERC7579Module {}

/**
 * @title IERC7579Fallback
 * @notice Interface for fallback handler modules (type ID: 3)
 * @dev Fallback handlers don't have additional interface requirements beyond IERC7579Module
 */
interface IERC7579Fallback is IERC7579Module {}

/**
 * @title IERC7579Hook
 * @notice Interface for hook modules (type ID: 4)
 */
interface IERC7579Hook is IERC7579Module {
    /**
     * @notice Pre-execution hook
     * @param msgSender Original message sender
     * @param msgValue Message value
     * @param msgData Message data
     * @return hookData Data to pass to postCheck
     */
    function preCheck(
        address msgSender,
        uint256 msgValue,
        bytes calldata msgData
    ) external returns (bytes memory hookData);

    /**
     * @notice Post-execution hook
     * @param hookData Data from preCheck
     */
    function postCheck(bytes calldata hookData) external;
}

/**
 * @title Execution
 * @notice Struct for batch executions
 */
struct Execution {
    address target;
    uint256 value;
    bytes callData;
}

/**
 * @title CallType
 * @notice Execution call type constants
 */
library CallType {
    bytes1 internal constant CALL = 0x00;
    bytes1 internal constant BATCH_CALL = 0x01;
    bytes1 internal constant STATIC_CALL = 0xFE;
    bytes1 internal constant DELEGATE_CALL = 0xFF;
}

/**
 * @title ExecType
 * @notice Execution error handling type constants
 */
library ExecType {
    bytes1 internal constant DEFAULT = 0x00; // Revert on failure
    bytes1 internal constant TRY = 0x01; // Continue on failure
}

/**
 * @title ModuleType
 * @notice Module type ID constants
 */
library ModuleType {
    uint256 internal constant VALIDATOR = 1;
    uint256 internal constant EXECUTOR = 2;
    uint256 internal constant FALLBACK = 3;
    uint256 internal constant HOOK = 4;
}
