//SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
import {OwnersAndThreshouldManager} from "./OwnersAndThreshouldManager.sol";
import {IAccount} from "account-abstraction/contracts/interfaces/IAccount.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {SIG_VALIDATION_FAILED} from "account-abstraction/contracts/core/Helpers.sol";
import {Exec} from "account-abstraction/contracts/utils/Exec.sol";

/**
 * @title SafeSocial
 * @notice Multi-sig wallet contract for Account Abstraction (ERC-4337)
 * @dev WARNING: This contract should ONLY be deployed via SafeSocialFactory.
 *      Directly deployed wallets will NOT be registered in the factory and will
 *      be rejected by SocialPaymaster. If deployed directly, users will not be
 *      able to use the paymaster and payment using other tokens.
 *      Always use SafeSocialFactory.deployWallet() or
 *      SafeSocialFactory.deployWalletDeterministic() to create wallets.
 */
contract SafeSocial is IAccount, OwnersAndThreshouldManager {
    ////Type Declarations////
    /**
     * @notice Call structure for batch execution
     * @param target Target address to call
     * @param value Amount of ETH (in wei) to send with the call
     * @param functionData Calldata to send to the target address
     */
    struct Call {
        address target;
        uint256 value;
        bytes functionData;
    }

    ////State Variables////
    IEntryPoint private immutable I_ENTRY_POINT;
    uint256 private constant SIGNATURE_VALIDITY_PERIOD = 1 days;

    ////Events////

    ////Errors////
    error SafeSocial__NotFromEntryPoint();
    error SafeSocial__ExecuteFailed(bytes returnData);
    error SafeSocial__ExecuteBatchFailed(bytes returnData, uint256 index);
    error SafeSocial__InvalidNonce();
    error SafeSocial__PrefundFailed();

    ////Modifiers////
    /**
     * @notice Restrict function access to EntryPoint only
     * @dev Ensures that only the EntryPoint contract can call protected functions
     * @custom:reverts SafeSocial__NotFromEntryPoint If msg.sender is not the EntryPoint contract
     */
    modifier onlyEntryPoint() {
        if (msg.sender != address(I_ENTRY_POINT)) {
            revert SafeSocial__NotFromEntryPoint();
        }
        _;
    }

    ////Constructor////
    /**
     * @notice Initialize SafeSocial wallet with owners, threshold, and EntryPoint
     * @dev Deploys a new multi-signature wallet. Should only be called via SafeSocialFactory.
     * @param owners Array of owner addresses (must be non-empty, no duplicates, no zero addresses)
     * @param threshould Minimum number of signatures required (must be > 0 and <= owners.length)
     * @param entryPointAddress Address of the ERC-4337 EntryPoint contract
     * @custom:reverts OwnersAndThreshouldManager__NeedAtLeastOneOwner If owners array is empty
     * @custom:reverts OwnersAndThreshouldManager__InvalidThreshould If threshold is 0 or > owners.length
     * @custom:reverts OwnersAndThreshouldManager__InvalidOwnerAddress If any owner is address(0)
     * @custom:reverts OwnersAndThreshouldManager__OwnerAlreadyExists If duplicate owners found
     */
    constructor(address[] memory owners, uint256 threshould, address entryPointAddress)
        OwnersAndThreshouldManager(owners, threshould)
    {
        I_ENTRY_POINT = IEntryPoint(entryPointAddress);
    }

    ////External Functions////
    /**
     * @notice Execute a single call to a target address
     * @dev Can only be called by EntryPoint. Executes a call with specified value and data.
     * @param dest Target address to call
     * @param value Amount of ETH (in wei) to send with the call
     * @param functionData Calldata to send to the target address
     * @custom:reverts SafeSocial__ExecuteFailed If the call fails
     */
    function execute(address dest, uint256 value, bytes calldata functionData) external onlyEntryPoint {
        bool success = Exec.call(dest, value, functionData, gasleft());
        if (!success) {
            revert SafeSocial__ExecuteFailed(Exec.getReturnData(0));
        }
    }

    /**
     * @notice Execute multiple calls in a single transaction
     * @dev Can only be called by EntryPoint. Executes all calls sequentially.
     *      If a single call fails, the entire batch reverts with the original error.
     *      If multiple calls fail, reverts with SafeSocial__ExecuteBatchFailed including the index.
     * @param calls Array of Call structs containing target, value, and functionData
     * @custom:reverts SafeSocial__ExecuteBatchFailed If any call fails (includes failed call index)
     */
    function executeBatch(Call[] calldata calls) external onlyEntryPoint {
        uint256 callsLength = calls.length;

        for (uint256 i = 0; i < callsLength; i++) {
            Call calldata call = calls[i];

            // Use Exec.call for safer gas handling
            bool success = Exec.call(call.target, call.value, call.functionData, gasleft());

            if (!success) {
                // If single call, preserve original revert reason
                if (callsLength == 1) {
                    Exec.revertWithReturnData();
                } else {
                    // Multiple calls: wrap error with index
                    revert SafeSocial__ExecuteBatchFailed(Exec.getReturnData(0), i);
                }
            }
        }
    }

    /**
     * @notice Validate a UserOperation according to ERC-4337
     * @dev Called by EntryPoint during handleOps. Validates signatures, nonce, and handles prefunding.
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation (computed by EntryPoint)
     * @param missingAccountFunds Amount of ETH needed to cover gas costs (will be deposited if > 0)
     * @return validationData Packed validation data containing aggregator, validUntil, and validAfter
     *                      Returns SIG_VALIDATION_FAILED if signature validation fails
     */
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        onlyEntryPoint
        returns (uint256 validationData)
    {
        validationData = _validateSignature(userOp, userOpHash);
        _validateNonce(userOp.nonce);
        _payPrefund(missingAccountFunds);
    }

    /**
     * @notice Receive ETH sent to the wallet
     * @dev Allows the wallet to receive ETH deposits directly
     *      ETH can be used to fund the EntryPoint deposit for gas payments
     * @notice This function is called automatically when ETH is sent to the wallet
     */
    receive() external payable {}

    /**
     * @notice Add a new owner to the wallet
     * @dev Adds a new owner to the multi-signature wallet. Can only be called via EntryPoint (through execute function).
     *      Requires threshold number of signatures to execute via UserOperation.
     * @param newOwner Address of the new owner to add (must not be address(0) or existing owner)
     * @custom:reverts SafeSocial__NotFromEntryPoint If called directly (must be called via execute())
     * @custom:reverts OwnersAndThreshouldManager__InvalidOwnerAddress If newOwner is address(0)
     * @custom:reverts OwnersAndThreshouldManager__OwnerAlreadyExists If owner already exists
     * @custom:emits OwnerAdded When owner is successfully added
     */
    function addOwner(address newOwner) external {
        // Can only be called from within the contract itself (via execute())
        // execute() has onlyEntryPoint modifier, ensuring EntryPoint is the caller
        // Multi-sig validation happens at validateUserOp level
        if (msg.sender != address(this)) {
            revert SafeSocial__NotFromEntryPoint();
        }
        _addOwner(newOwner);
    }

    /**
     * @notice Remove an owner from the wallet
     * @dev Removes an owner from the multi-signature wallet. Can only be called via EntryPoint (through execute function).
     *      Requires threshold number of signatures to execute via UserOperation.
     *      Uses swap-with-last-element for O(1) removal (changes owner array order).
     * @param ownerToRemove Address of the owner to remove (must be an existing owner)
     * @custom:reverts SafeSocial__NotFromEntryPoint If called directly (must be called via execute())
     * @custom:reverts OwnersAndThreshouldManager__InvalidOwnerAddress If ownerToRemove is address(0)
     * @custom:reverts OwnersAndThreshouldManager__OwnerNotFound If owner is not found
     * @custom:reverts OwnersAndThreshouldManager__RemovalWouldViolateThreshold If removal would make owners.length < threshold
     * @custom:emits OwnerRemoved When owner is successfully removed
     */
    function removeOwner(address ownerToRemove) external {
        // Can only be called from within the contract itself (via execute())
        // execute() has onlyEntryPoint modifier, ensuring EntryPoint is the caller
        // Multi-sig validation happens at validateUserOp level
        if (msg.sender != address(this)) {
            revert SafeSocial__NotFromEntryPoint();
        }
        _removeOwner(ownerToRemove);
    }

    /**
     * @notice Update the threshold required for executing transactions
     * @dev Updates the minimum number of signatures required for execution. Can only be called via EntryPoint (through execute function).
     *      Requires threshold number of signatures to execute via UserOperation.
     * @param newThreshould New threshold value (must be > 0 and <= owners.length)
     * @custom:reverts SafeSocial__NotFromEntryPoint If called directly (must be called via execute())
     * @custom:reverts OwnersAndThreshouldManager__InvalidThreshould If threshold is 0 or > owners.length
     * @custom:emits ThreshouldUpdated When threshold is successfully updated
     */
    function updateThreshould(uint256 newThreshould) external {
        // Can only be called from within the contract itself (via execute())
        // execute() has onlyEntryPoint modifier, ensuring EntryPoint is the caller
        // Multi-sig validation happens at validateUserOp level
        if (msg.sender != address(this)) {
            revert SafeSocial__NotFromEntryPoint();
        }
        _updateThreshould(newThreshould);
    }

    ////Internal Functions////
    /**
     * @notice Deposit ETH to EntryPoint to cover gas costs
     * @dev Called during validateUserOp if the account has insufficient deposit
     * @param missingAccountFunds Amount of ETH needed to cover gas costs
     * @custom:reverts SafeSocial__PrefundFailed If the ETH transfer to EntryPoint fails
     */
    function _payPrefund(uint256 missingAccountFunds) internal {
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds, gas: type(uint256).max}("");
            if (!success) {
                revert SafeSocial__PrefundFailed();
            }
        }
    }

    /**
     * @notice Validate signatures against threshold requirement
     * @dev Checks if enough valid signatures from owners are provided. Sets validity period to 1 day.
     *      NOTE: Replay protection is provided by the nonce being part of userOpHash (managed by EntryPoint).
     *      The validUntil field limits pending UserOp validity, not replay protection.
     * @param userOp The UserOperation containing signatures
     * @param userOpHash Hash of the UserOperation to verify signatures against
     * @return validationData Packed validation data:
     *                      - aggregator: address(0) (no aggregator)
     *                      - validUntil: block.timestamp + 1 day
     *                      - validAfter: 0 (immediate validity)
     *                      Returns SIG_VALIDATION_FAILED if threshold not met
     */
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        returns (uint256 validationData)
    {
        bool isValid = _checkThreshould(userOpHash, userOp.signature);
        if (!isValid) {
            return SIG_VALIDATION_FAILED;
        }
        // Pack validationData according to ERC-4337 format:
        // Format: aggregator (bits 0-160) | validUntil (bits 160-208) | validAfter (bits 208-256)
        // aggregator = address(0) for no aggregator (SIG_VALIDATION_SUCCESS = 0)
        uint48 validAfter = 0;
        uint48 validUntil = uint48(block.timestamp + SIGNATURE_VALIDITY_PERIOD);
        validationData = uint160(0) | (uint256(validUntil) << 160) | (uint256(validAfter) << (160 + 48));
        return validationData;
    }

    /**
     * @notice Validate the nonce of the UserOperation
     * @dev EntryPoint handles nonce validation and sequential ordering before calling validateUserOp.
     *      This function is kept for interface compliance but relies on EntryPoint's nonce management.
     *      No additional validation is performed here.
     * @param nonce The nonce to validate (already validated by EntryPoint)
     */
    function _validateNonce(uint256 nonce) internal pure {
        // EntryPoint manages nonces and ensures sequential ordering
        // This check is redundant but kept for explicit validation
        // EntryPoint will revert if nonce is invalid before calling validateUserOp
        // No additional validation needed here
        (nonce); // Silence unused parameter warning
    }

    ////View Functions////
    /**
     * @notice Get the EntryPoint address
     * @return The address of the EntryPoint contract used by this wallet
     */
    function entryPoint() public view returns (address) {
        return address(I_ENTRY_POINT);
    }
}
