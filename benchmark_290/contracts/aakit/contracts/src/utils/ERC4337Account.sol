// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {IAccount, PackedUserOperation, IEntryPoint} from "../interfaces/IERC4337.sol";

/**
 * @title ERC4337Account
 * @notice Base implementation for ERC-4337 compliant accounts
 * @dev Provides common functionality for account abstraction
 */
abstract contract ERC4337Account is IAccount {
    // EntryPoint address
    address public immutable entryPoint;

    // Nonce key for cross-chain replayable operations
    uint192 internal constant REPLAYABLE_NONCE_KEY = type(uint192).max;

    // Validation constants
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    // Events
    event AccountInitialized(address indexed entryPoint, address indexed account);

    // Errors
    error InvalidEntryPoint();
    error InvalidNonceKey(uint192 key);
    error OnlyEntryPoint();
    error OnlyEntryPointOrSelf();
    error ValidationFailed();

    /**
     * @notice Constructor
     * @param _entryPoint Address of the EntryPoint contract
     */
    constructor(address _entryPoint) {
        if (_entryPoint == address(0)) revert InvalidEntryPoint();
        entryPoint = _entryPoint;
    }

    /**
     * @notice Validate user operation
     * @param userOp User operation to validate
     * @param userOpHash Hash of the user operation
     * @param missingAccountFunds Funds needed to be deposited to EntryPoint
     * @return validationData Packed validation data
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual returns (uint256 validationData) {
        _requireFromEntryPoint();
        
        // Check if this is a cross-chain replayable operation
        userOpHash = _replayableUserOpHash(userOp, userOpHash);

        // Validate signature
        validationData = _validateSignature(userOp, userOpHash);

        // Pay required funds to EntryPoint
        _payPrefund(missingAccountFunds);
    }

    /**
     * @notice Deposit funds to EntryPoint
     */
    function addDeposit() external payable {
        IEntryPoint(entryPoint).depositTo{value: msg.value}(address(this));
    }

    /**
     * @notice Get deposit info from EntryPoint
     * @return deposit Current deposit amount
     */
    function getDeposit() public view returns (uint256) {
        return IEntryPoint(entryPoint).getDepositInfo(address(this)).deposit;
    }

    /**
     * @notice Withdraw from EntryPoint
     * @param withdrawAddress Address to withdraw to
     * @param amount Amount to withdraw
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) external virtual {
        _checkOwner();
        IEntryPoint(entryPoint).withdrawTo(withdrawAddress, amount);
    }

    /**
     * @notice Get nonce from EntryPoint
     * @param key Nonce key
     * @return Nonce value
     */
    function getNonce(uint192 key) public view returns (uint256) {
        return IEntryPoint(entryPoint).getNonce(address(this), key);
    }

    /**
     * @notice Check if operation uses cross-chain replayable nonce
     * @param userOp User operation
     * @return True if replayable
     */
    function _isReplayableNonce(
        PackedUserOperation calldata userOp
    ) internal pure returns (bool) {
        uint192 key = uint192(userOp.nonce >> 64);
        return key == REPLAYABLE_NONCE_KEY;
    }

    /**
     * @notice Compute userOpHash for replayable operations
     * @param userOp User operation
     * @param userOpHash Original userOpHash
     * @return Modified userOpHash if replayable, original otherwise
     */
    function _replayableUserOpHash(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (bytes32) {
        // Check if calling executeWithoutChainIdValidation
        if (
            userOp.callData.length >= 4 &&
            bytes4(userOp.callData[0:4]) == this.executeWithoutChainIdValidation.selector
        ) {
            // Must use replayable nonce key
            if (!_isReplayableNonce(userOp)) {
                revert InvalidNonceKey(uint192(userOp.nonce >> 64));
            }
            
            // Recompute hash without chain ID
            return _getUserOpHashWithoutChainId(userOp);
        } else {
            // Regular operation must NOT use replayable nonce
            if (_isReplayableNonce(userOp)) {
                revert InvalidNonceKey(uint192(userOp.nonce >> 64));
            }
            
            return userOpHash;
        }
    }

    /**
     * @notice Compute userOpHash without chain ID
     * @param userOp User operation
     * @return Hash without chain ID
     */
    function _getUserOpHashWithoutChainId(
        PackedUserOperation calldata userOp
    ) internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _hashUserOp(userOp),
                entryPoint
                // Note: chainId intentionally omitted
            )
        );
    }

    /**
     * @notice Hash user operation (without entryPoint and chainId)
     * @param userOp User operation
     * @return Hash of user operation
     */
    function _hashUserOp(
        PackedUserOperation calldata userOp
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                userOp.sender,
                userOp.nonce,
                keccak256(userOp.initCode),
                keccak256(userOp.callData),
                userOp.accountGasLimits,
                userOp.preVerificationGas,
                userOp.gasFees,
                keccak256(userOp.paymasterAndData)
            )
        );
    }

    /**
     * @notice Pay prefund to EntryPoint
     * @param missingAccountFunds Amount to pay
     */
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool success, ) = payable(entryPoint).call{
                value: missingAccountFunds,
                gas: type(uint256).max
            }("");
            require(success, "Failed to pay prefund");
        }
    }

    /**
     * @notice Require caller is EntryPoint
     */
    function _requireFromEntryPoint() internal view {
        if (msg.sender != entryPoint) revert OnlyEntryPoint();
    }

    /**
     * @notice Require caller is EntryPoint or self
     */
    function _requireFromEntryPointOrSelf() internal view {
        if (msg.sender != entryPoint && msg.sender != address(this)) {
            revert OnlyEntryPointOrSelf();
        }
    }

    /**
     * @notice Validate signature (must be implemented by child)
     * @param userOp User operation
     * @param userOpHash Hash to validate against
     * @return validationData Packed validation data
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual returns (uint256 validationData);

    /**
     * @notice Check if caller is owner (must be implemented by child)
     */
    function _checkOwner() internal view virtual;

    /**
     * @notice Execute without chain ID validation (for cross-chain ops)
     * @param data Calldata to execute
     */
    function executeWithoutChainIdValidation(bytes calldata data) external payable virtual;

    /**
     * @notice Receive ETH
     */
    receive() external payable {}
}
