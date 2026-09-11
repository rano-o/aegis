// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IValidator, IModule } from "../interfaces/IModule.sol";
import { IEntryPoint } from "../interfaces/IEntryPoint.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title SessionKeyModule
 * @author ERC-4337 Account Abstraction Toolkit
 * @notice Validator module enabling delegated signing with restricted permissions
 *
 * @dev Session keys allow:
 *      - Temporary signing authority without exposing main key
 *      - Per-key spending limits and target restrictions
 *      - Time-bounded sessions (validUntil/validAfter)
 *      - Revocation at any time by account owner
 *
 * Use Cases:
 * +-----------------------------------------------------------------------------+
 * |                       SESSION KEY USE CASES                                 |
 * +-----------------------------------------------------------------------------+
 * |                                                                             |
 * |   Gaming                                                                    |
 * |   - Hot wallet for in-game transactions                                     |
 * |   - Limit: 0.1 ETH per tx, game contract only                               |
 * |   - Expires after gaming session                                            |
 * |                                                                             |
 * |   Mobile App                                                                |
 * |   - Device-specific key stored in secure enclave                            |
 * |   - Limit: Daily spending cap                                               |
 * |   - Instant revocation on device loss                                       |
 * |                                                                             |
 * |   Automation                                                                |
 * |   - Bot key for DCA, yield farming                                          |
 * |   - Limit: Specific DEX contracts only                                      |
 * |   - No ETH transfers, only token swaps                                      |
 * |                                                                             |
 * |   Recovery                                                                  |
 * |   - Trusted friend can initiate recovery                                    |
 * |   - Limit: Only call recovery module                                        |
 * |   - Time-locked execution                                                   |
 * |                                                                             |
 * +-----------------------------------------------------------------------------+
 *
 * Permission Structure:
 * - Target whitelist: Specific contracts the key can interact with
 * - Function selector whitelist: Specific functions allowed per target
 * - Value limit: Maximum ETH per transaction
 * - Spending limit: Maximum total ETH across all transactions
 * - Valid time window: validAfter to validUntil
 */
contract SessionKeyModule is IValidator {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @notice EIP-1271 magic values
    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAILED = 0xffffffff;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Session key permissions
     * @param validAfter Session start timestamp (0 = immediate)
     * @param validUntil Session end timestamp (0 = never expires)
     * @param valueLimit Maximum ETH value per transaction
     * @param spendingLimit Total spending limit (decremented on use)
     * @param approved Whether session is active
     */
    struct SessionData {
        uint48 validAfter;
        uint48 validUntil;
        uint128 valueLimit;
        uint128 spendingLimit;
        bool approved;
    }

    /**
     * @notice Target-specific permissions
     * @param allowed Whether target is allowed
     * @param selectors Allowed function selectors (empty = all allowed)
     */
    struct TargetPermission {
        bool allowed;
        bytes4[] selectors;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Session data per account per session key
    /// account => sessionKey => SessionData
    mapping(address => mapping(address => SessionData)) public sessions;

    /// @notice Target permissions per account per session key
    /// account => sessionKey => target => TargetPermission
    mapping(address => mapping(address => mapping(address => TargetPermission))) public targetPermissions;

    /// @notice Track spending per session key
    /// account => sessionKey => totalSpent
    mapping(address => mapping(address => uint256)) public totalSpent;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event SessionKeyAdded(
        address indexed account,
        address indexed sessionKey,
        uint48 validAfter,
        uint48 validUntil,
        uint128 valueLimit,
        uint128 spendingLimit
    );

    event SessionKeyRevoked(address indexed account, address indexed sessionKey);

    event TargetPermissionSet(
        address indexed account,
        address indexed sessionKey,
        address indexed target,
        bool allowed,
        bytes4[] selectors
    );

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error SessionNotFound();
    error SessionExpired();
    error SessionNotYetValid();
    error TargetNotAllowed();
    error SelectorNotAllowed();
    error ValueLimitExceeded();
    error SpendingLimitExceeded();
    error InvalidSessionKey();

    /*//////////////////////////////////////////////////////////////
                          MODULE INTERFACE
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IModule
     */
    function onInstall(bytes calldata data) external override {
        // Optionally add initial session keys
        if (data.length > 0) {
            (
                address sessionKey,
                uint48 validAfter,
                uint48 validUntil,
                uint128 valueLimit,
                uint128 spendingLimit,
                address[] memory targets,
                bytes4[][] memory selectors
            ) = abi.decode(data, (address, uint48, uint48, uint128, uint128, address[], bytes4[][]));

            _addSessionKey(msg.sender, sessionKey, validAfter, validUntil, valueLimit, spendingLimit);

            for (uint256 i = 0; i < targets.length; i++) {
                _setTargetPermission(msg.sender, sessionKey, targets[i], true, selectors[i]);
            }
        }
    }

    /**
     * @inheritdoc IModule
     */
    function onUninstall(bytes calldata) external override {
        // Module uninstall - sessions are automatically invalidated
        // as the module is no longer active on the account
    }

    /**
     * @inheritdoc IModule
     */
    function isModuleType(ModuleType moduleType) external pure override returns (bool) {
        return moduleType == ModuleType.Validator;
    }

    /**
     * @inheritdoc IModule
     */
    function moduleTypes() external pure override returns (uint256) {
        return 1 << uint256(ModuleType.Validator);
    }

    /*//////////////////////////////////////////////////////////////
                       VALIDATOR INTERFACE
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IValidator
     * @dev Signature format: [sessionKey (20)] [signature (65)]
     */
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256 validationData) {
        address account = userOp.sender;
        bytes calldata signature = userOp.signature;

        // Extract session key from signature
        // Format: [module address (20)] [sessionKey (20)] [signature (65)]
        if (signature.length < 105) {
            return SIG_VALIDATION_FAILED;
        }

        address sessionKey = address(bytes20(signature[20:40]));
        bytes calldata sessionSignature = signature[40:];

        // Get session data
        SessionData storage session = sessions[account][sessionKey];
        if (!session.approved) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify signature from session key
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError error,) = ethSignedHash.tryRecover(sessionSignature);

        if (error != ECDSA.RecoverError.NoError || recovered != sessionKey) {
            return SIG_VALIDATION_FAILED;
        }

        // Validate permissions (decode callData to check target/selector/value)
        if (!_validatePermissions(account, sessionKey, userOp.callData)) {
            return SIG_VALIDATION_FAILED;
        }

        // Pack validUntil and validAfter into validation data
        return _packValidationData(false, session.validUntil, session.validAfter);
    }

    /**
     * @inheritdoc IValidator
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        // Extract session key
        if (signature.length < 85) {
            return EIP1271_FAILED;
        }

        address sessionKey = address(bytes20(signature[0:20]));
        bytes calldata sessionSignature = signature[20:];

        SessionData storage session = sessions[sender][sessionKey];
        if (!session.approved) {
            return EIP1271_FAILED;
        }

        // Check time bounds
        if (session.validUntil != 0 && block.timestamp > session.validUntil) {
            return EIP1271_FAILED;
        }
        if (session.validAfter != 0 && block.timestamp < session.validAfter) {
            return EIP1271_FAILED;
        }

        // Verify signature
        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError error,) = ethSignedHash.tryRecover(sessionSignature);

        if (error == ECDSA.RecoverError.NoError && recovered == sessionKey) {
            return EIP1271_SUCCESS;
        }

        return EIP1271_FAILED;
    }

    /*//////////////////////////////////////////////////////////////
                      SESSION KEY MANAGEMENT
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Add a new session key
     * @param sessionKey The session key address
     * @param validAfter Start timestamp
     * @param validUntil End timestamp
     * @param valueLimit Max value per tx
     * @param spendingLimit Total spending limit
     */
    function addSessionKey(
        address sessionKey,
        uint48 validAfter,
        uint48 validUntil,
        uint128 valueLimit,
        uint128 spendingLimit
    ) external {
        _addSessionKey(msg.sender, sessionKey, validAfter, validUntil, valueLimit, spendingLimit);
    }

    /**
     * @notice Revoke a session key
     * @param sessionKey The session key to revoke
     */
    function revokeSessionKey(address sessionKey) external {
        sessions[msg.sender][sessionKey].approved = false;
        emit SessionKeyRevoked(msg.sender, sessionKey);
    }

    /**
     * @notice Set permissions for a target contract
     * @param sessionKey The session key
     * @param target The target contract
     * @param allowed Whether the target is allowed
     * @param selectors Allowed function selectors (empty = all)
     */
    function setTargetPermission(
        address sessionKey,
        address target,
        bool allowed,
        bytes4[] calldata selectors
    ) external {
        _setTargetPermission(msg.sender, sessionKey, target, allowed, selectors);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _addSessionKey(
        address account,
        address sessionKey,
        uint48 validAfter,
        uint48 validUntil,
        uint128 valueLimit,
        uint128 spendingLimit
    ) internal {
        if (sessionKey == address(0)) {
            revert InvalidSessionKey();
        }

        sessions[account][sessionKey] = SessionData({
            validAfter: validAfter,
            validUntil: validUntil,
            valueLimit: valueLimit,
            spendingLimit: spendingLimit,
            approved: true
        });

        emit SessionKeyAdded(account, sessionKey, validAfter, validUntil, valueLimit, spendingLimit);
    }

    function _setTargetPermission(
        address account,
        address sessionKey,
        address target,
        bool allowed,
        bytes4[] memory selectors
    ) internal {
        targetPermissions[account][sessionKey][target] = TargetPermission({
            allowed: allowed,
            selectors: selectors
        });

        emit TargetPermissionSet(account, sessionKey, target, allowed, selectors);
    }

    /**
     * @notice Validate that the callData adheres to session permissions
     * @dev Decodes execute() or executeBatch() calls
     */
    function _validatePermissions(
        address account,
        address sessionKey,
        bytes calldata callData
    ) internal returns (bool) {
        SessionData storage session = sessions[account][sessionKey];

        // Decode the call - assuming standard execute(address,uint256,bytes) signature
        if (callData.length < 4) {
            return false;
        }

        bytes4 selector = bytes4(callData[:4]);

        // Handle single execute
        if (selector == bytes4(keccak256("execute(address,uint256,bytes)"))) {
            (address target, uint256 value, bytes memory data) = abi.decode(callData[4:], (address, uint256, bytes));
            return _validateSingleCall(account, sessionKey, session, target, value, data);
        }

        // Handle batch execute
        if (selector == bytes4(keccak256("executeBatch(address[],uint256[],bytes[])"))) {
            (address[] memory targets, uint256[] memory values, bytes[] memory datas) =
                abi.decode(callData[4:], (address[], uint256[], bytes[]));

            for (uint256 i = 0; i < targets.length; i++) {
                if (!_validateSingleCall(account, sessionKey, session, targets[i], values[i], datas[i])) {
                    return false;
                }
            }
            return true;
        }

        return false;
    }

    function _validateSingleCall(
        address account,
        address sessionKey,
        SessionData storage session,
        address target,
        uint256 value,
        bytes memory data
    ) internal returns (bool) {
        // Check value limit
        if (value > session.valueLimit) {
            return false;
        }

        // Check spending limit
        uint256 spent = totalSpent[account][sessionKey];
        if (spent + value > session.spendingLimit) {
            return false;
        }

        // Update spending
        totalSpent[account][sessionKey] = spent + value;

        // Check target permission
        TargetPermission storage perm = targetPermissions[account][sessionKey][target];
        if (!perm.allowed) {
            // Check if wildcard (address(0)) is allowed
            if (!targetPermissions[account][sessionKey][address(0)].allowed) {
                return false;
            }
        }

        // Check selector permission
        if (data.length >= 4 && perm.selectors.length > 0) {
            bytes4 callSelector = bytes4(data);
            bool selectorAllowed = false;
            for (uint256 i = 0; i < perm.selectors.length; i++) {
                if (perm.selectors[i] == callSelector) {
                    selectorAllowed = true;
                    break;
                }
            }
            if (!selectorAllowed) {
                return false;
            }
        }

        return true;
    }

    function _packValidationData(
        bool sigFailed,
        uint48 validUntil,
        uint48 validAfter
    ) internal pure returns (uint256) {
        return (sigFailed ? 1 : 0) | (uint256(validUntil) << 160) | (uint256(validAfter) << 208);
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get session data for a key
     */
    function getSessionData(address account, address sessionKey) external view returns (SessionData memory) {
        return sessions[account][sessionKey];
    }

    /**
     * @notice Check if a session is valid
     */
    function isSessionValid(address account, address sessionKey) external view returns (bool) {
        SessionData storage session = sessions[account][sessionKey];
        if (!session.approved) return false;
        if (session.validUntil != 0 && block.timestamp > session.validUntil) return false;
        if (session.validAfter != 0 && block.timestamp < session.validAfter) return false;
        return true;
    }
}
