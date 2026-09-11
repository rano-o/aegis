// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IValidator, IModule } from "../interfaces/IModule.sol";
import { IEntryPoint } from "../interfaces/IEntryPoint.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

/**
 * @title MultisigValidatorModule
 * @author ERC-4337 Account Abstraction Toolkit
 * @notice Validator module requiring M-of-N signatures for UserOperation validation
 *
 * @dev Enables shared control of smart accounts:
 *      - Multiple signers with equal weight
 *      - Configurable threshold (M of N)
 *      - Sorted signatures for gas efficiency
 *
 * Use Cases:
 * +-----------------------------------------------------------------------------+
 * |                       MULTISIG USE CASES                                    |
 * +-----------------------------------------------------------------------------+
 * |                                                                             |
 * |   Company Treasury                                                          |
 * |   - 3-of-5 executives required for transactions                             |
 * |   - No single point of failure                                              |
 * |   - Audit trail via on-chain signatures                                     |
 * |                                                                             |
 * |   Family Account                                                            |
 * |   - 2-of-3 family members for large purchases                               |
 * |   - Shared vacation fund                                                    |
 * |   - Estate planning                                                         |
 * |                                                                             |
 * |   Partnership                                                               |
 * |   - 2-of-2 for all transactions                                             |
 * |   - Equal control                                                           |
 * |   - Mutual consent required                                                 |
 * |                                                                             |
 * |   Enhanced Security                                                         |
 * |   - 2-of-3 with hardware wallet + phone + backup                            |
 * |   - Defense in depth                                                        |
 * |   - Key compromise resistance                                               |
 * |                                                                             |
 * +-----------------------------------------------------------------------------+
 *
 * Signature Format:
 * [module (20)] [threshold (1)] [sig1 (65)] [sig2 (65)] ... [sigN (65)]
 *
 * Signatures must be sorted by signer address (ascending) for gas efficiency
 * and to prevent signature reuse attacks.
 */
contract MultisigValidatorModule is IValidator {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    /*//////////////////////////////////////////////////////////////
                               CONSTANTS
    //////////////////////////////////////////////////////////////*/

    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    bytes4 internal constant EIP1271_SUCCESS = 0x1626ba7e;
    bytes4 internal constant EIP1271_FAILED = 0xffffffff;

    /// @notice Maximum number of signers
    uint256 public constant MAX_SIGNERS = 10;

    /*//////////////////////////////////////////////////////////////
                                STRUCTS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Multisig configuration for an account
     * @param signers List of authorized signers
     * @param threshold Required number of signatures
     */
    struct MultisigConfig {
        address[] signers;
        uint256 threshold;
    }

    /*//////////////////////////////////////////////////////////////
                               STORAGE
    //////////////////////////////////////////////////////////////*/

    /// @notice Multisig config per account
    mapping(address => MultisigConfig) public configs;

    /// @notice Signer lookup (account => signer => isSigner)
    mapping(address => mapping(address => bool)) public isSigner;

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event MultisigConfigured(address indexed account, address[] signers, uint256 threshold);
    event SignerAdded(address indexed account, address indexed signer);
    event SignerRemoved(address indexed account, address indexed signer);
    event ThresholdChanged(address indexed account, uint256 newThreshold);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error InvalidThreshold();
    error TooManySigners();
    error SignerAlreadyExists();
    error SignerNotFound();
    error InvalidSignatureCount();
    error DuplicateSignature();
    error InvalidSignerOrder();
    error SignerNotAuthorized();
    error ZeroAddress();

    /*//////////////////////////////////////////////////////////////
                          MODULE INTERFACE
    //////////////////////////////////////////////////////////////*/

    /**
     * @inheritdoc IModule
     * @dev Initialize with signers and threshold
     */
    function onInstall(bytes calldata data) external override {
        if (data.length == 0) return;

        (address[] memory signers, uint256 threshold) = abi.decode(data, (address[], uint256));
        _setupMultisig(msg.sender, signers, threshold);
    }

    /**
     * @inheritdoc IModule
     */
    function onUninstall(bytes calldata) external override {
        // Clear signers
        MultisigConfig storage config = configs[msg.sender];
        for (uint256 i = 0; i < config.signers.length; i++) {
            isSigner[msg.sender][config.signers[i]] = false;
        }
        delete configs[msg.sender];
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
     * @dev Signature format: [module (20)] [sig1 (65)] [sig2 (65)] ... [sigN (65)]
     *      Signatures must be sorted by signer address (ascending)
     */
    function validateUserOp(
        IEntryPoint.PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external view override returns (uint256 validationData) {
        address account = userOp.sender;
        MultisigConfig storage config = configs[account];

        if (config.threshold == 0) {
            return SIG_VALIDATION_FAILED;
        }

        bytes calldata signature = userOp.signature;

        // Skip module address prefix (20 bytes)
        if (signature.length < 20) {
            return SIG_VALIDATION_FAILED;
        }

        bytes calldata sigs = signature[20:];

        // Verify we have enough signatures
        uint256 sigCount = sigs.length / 65;
        if (sigCount < config.threshold) {
            return SIG_VALIDATION_FAILED;
        }

        // Verify all signatures
        bytes32 ethSignedHash = userOpHash.toEthSignedMessageHash();
        address lastSigner = address(0);

        for (uint256 i = 0; i < config.threshold; i++) {
            bytes calldata sig = sigs[i * 65:(i + 1) * 65];

            address recovered = ethSignedHash.recover(sig);

            // Check signer is authorized
            if (!isSigner[account][recovered]) {
                return SIG_VALIDATION_FAILED;
            }

            // Check signers are in ascending order (prevents duplicates)
            if (recovered <= lastSigner) {
                return SIG_VALIDATION_FAILED;
            }

            lastSigner = recovered;
        }

        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @inheritdoc IValidator
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        MultisigConfig storage config = configs[sender];

        if (config.threshold == 0) {
            return EIP1271_FAILED;
        }

        // Verify we have enough signatures
        uint256 sigCount = signature.length / 65;
        if (sigCount < config.threshold) {
            return EIP1271_FAILED;
        }

        bytes32 ethSignedHash = hash.toEthSignedMessageHash();
        address lastSigner = address(0);

        for (uint256 i = 0; i < config.threshold; i++) {
            bytes calldata sig = signature[i * 65:(i + 1) * 65];

            address recovered = ethSignedHash.recover(sig);

            if (!isSigner[sender][recovered]) {
                return EIP1271_FAILED;
            }

            if (recovered <= lastSigner) {
                return EIP1271_FAILED;
            }

            lastSigner = recovered;
        }

        return EIP1271_SUCCESS;
    }

    /*//////////////////////////////////////////////////////////////
                      MULTISIG CONFIGURATION
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Setup multisig configuration
     * @param signers Array of signer addresses
     * @param threshold Required number of signatures
     */
    function setupMultisig(address[] calldata signers, uint256 threshold) external {
        _setupMultisig(msg.sender, signers, threshold);
    }

    /**
     * @notice Add a new signer
     * @param signer Address to add
     */
    function addSigner(address signer) external {
        if (signer == address(0)) {
            revert ZeroAddress();
        }

        MultisigConfig storage config = configs[msg.sender];

        if (config.signers.length >= MAX_SIGNERS) {
            revert TooManySigners();
        }
        if (isSigner[msg.sender][signer]) {
            revert SignerAlreadyExists();
        }

        config.signers.push(signer);
        isSigner[msg.sender][signer] = true;

        emit SignerAdded(msg.sender, signer);
    }

    /**
     * @notice Remove a signer
     * @param signer Address to remove
     */
    function removeSigner(address signer) external {
        MultisigConfig storage config = configs[msg.sender];

        if (!isSigner[msg.sender][signer]) {
            revert SignerNotFound();
        }

        // Ensure threshold is still valid after removal
        if (config.signers.length - 1 < config.threshold) {
            revert InvalidThreshold();
        }

        // Find and remove signer
        uint256 length = config.signers.length;
        for (uint256 i = 0; i < length; i++) {
            if (config.signers[i] == signer) {
                config.signers[i] = config.signers[length - 1];
                config.signers.pop();
                break;
            }
        }

        isSigner[msg.sender][signer] = false;

        emit SignerRemoved(msg.sender, signer);
    }

    /**
     * @notice Update threshold
     * @param newThreshold New threshold value
     */
    function setThreshold(uint256 newThreshold) external {
        MultisigConfig storage config = configs[msg.sender];

        if (newThreshold == 0 || newThreshold > config.signers.length) {
            revert InvalidThreshold();
        }

        config.threshold = newThreshold;

        emit ThresholdChanged(msg.sender, newThreshold);
    }

    /*//////////////////////////////////////////////////////////////
                         INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _setupMultisig(
        address account,
        address[] memory signers,
        uint256 threshold
    ) internal {
        if (signers.length > MAX_SIGNERS) {
            revert TooManySigners();
        }
        if (threshold == 0 || threshold > signers.length) {
            revert InvalidThreshold();
        }

        // Clear existing signers
        MultisigConfig storage config = configs[account];
        for (uint256 i = 0; i < config.signers.length; i++) {
            isSigner[account][config.signers[i]] = false;
        }

        // Set new signers
        config.signers = signers;
        config.threshold = threshold;

        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == address(0)) {
                revert ZeroAddress();
            }
            if (isSigner[account][signers[i]]) {
                revert SignerAlreadyExists();
            }
            isSigner[account][signers[i]] = true;
        }

        emit MultisigConfigured(account, signers, threshold);
    }

    /*//////////////////////////////////////////////////////////////
                              GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @notice Get multisig configuration for an account
     */
    function getConfig(address account) external view returns (MultisigConfig memory) {
        return configs[account];
    }

    /**
     * @notice Get signer count for an account
     */
    function getSignerCount(address account) external view returns (uint256) {
        return configs[account].signers.length;
    }

    /**
     * @notice Get threshold for an account
     */
    function getThreshold(address account) external view returns (uint256) {
        return configs[account].threshold;
    }

    /**
     * @notice Check if address is a signer for an account
     */
    function isSignerFor(address account, address signer) external view returns (bool) {
        return isSigner[account][signer];
    }
}
