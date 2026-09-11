// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {INexusAccount} from "./interfaces/INexusAccount.sol";
import {IEntryPoint} from "account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {UserOperationLib} from "account-abstraction/contracts/core/UserOperationLib.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS, _packValidationData} from "account-abstraction/contracts/core/Helpers.sol";

contract NexusAccount is INexusAccount, ReentrancyGuard {
    using UserOperationLib for PackedUserOperation;

    struct SessionKey {
        uint48 validUntil;
        uint256 gasLimit;
        bool active;
        bool hasTargetList;
    }

    struct Recovery {
        address newOwner;
        uint48 executeAfter;
        uint8 confirmations;
        bool executed;
    }

    address public owner;
    IEntryPoint public immutable entryPoint;
    bool public initialized;

    uint256 public constant RECOVERY_TIMELOCK = 1 days;
    uint256 public constant RECOVERY_THRESHOLD = 2;
    uint256 public constant MAX_GUARDIANS = 3;

    mapping(address => SessionKey) private sessionKeys;
    mapping(address => mapping(address => bool)) private sessionKeyTargets;
    mapping(address => address[]) private sessionKeyTargetList;

    mapping(address => bool) private guardians;
    uint256 private guardianTotal;

    mapping(bytes32 => Recovery) private recoveries;
    mapping(bytes32 => mapping(address => bool)) private recoveryConfirmations;
    uint256 private recoveryNonce;

    modifier onlyOwner() {
        require(msg.sender == owner, "account: not owner");
        _;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    receive() external payable {}

    function initialize(address _owner) external override {
        require(!initialized, "account: already initialized");
        initialized = true;
        owner = _owner;
        emit OwnerUpdated(address(0), _owner);
    }

    function transferOwnership(address newOwner) external override onlyOwner {
        address oldOwner = owner;
        owner = newOwner;
        emit OwnerUpdated(oldOwner, newOwner);
    }

    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        require(msg.sender == address(entryPoint), "account: not entrypoint");
        bytes32 digest = MessageHashUtils.toEthSignedMessageHash(userOpHash);
        address signer = ECDSA.recover(digest, userOp.signature);

        if (signer == owner) {
            validationData = SIG_VALIDATION_SUCCESS;
        } else if (sessionKeys[signer].active) {
            validationData = _validateSessionKeyUserOp(userOp, signer);
        } else {
            validationData = SIG_VALIDATION_FAILED;
        }

        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            success;
        }
    }

    function execute(address dest, uint256 value, bytes calldata func) external override nonReentrant {
        if (msg.sender == owner || msg.sender == address(entryPoint)) {
            _call(dest, value, func);
            return;
        }

        _requireValidSessionKeyExecution(msg.sender, dest);
        _call(dest, value, func);
    }

    function executeUserOp(PackedUserOperation calldata userOp, bytes32) external override {
        require(msg.sender == address(entryPoint), "account: not entrypoint");
        bytes calldata innerCall = userOp.callData[4:];
        (address dest, uint256 value, bytes memory func) = abi.decode(innerCall, (address, uint256, bytes));
        _call(dest, value, func);
    }

    function addSessionKey(
        address sessionKey,
        uint48 validUntil,
        uint256 gasLimit,
        address[] calldata targetContracts
    ) external override onlyOwner {
        require(sessionKey != address(0), "account: invalid session key");
        _clearSessionKeyTargets(sessionKey);

        SessionKey storage key = sessionKeys[sessionKey];
        key.validUntil = validUntil;
        key.gasLimit = gasLimit;
        key.active = true;
        key.hasTargetList = targetContracts.length > 0;

        if (targetContracts.length > 0) {
            address[] storage list = sessionKeyTargetList[sessionKey];
            for (uint256 i = 0; i < targetContracts.length; i++) {
                address target = targetContracts[i];
                sessionKeyTargets[sessionKey][target] = true;
                list.push(target);
            }
        }

        emit SessionKeyAdded(sessionKey, validUntil, gasLimit, targetContracts);
    }

    function removeSessionKey(address sessionKey) external override onlyOwner {
        _clearSessionKeyTargets(sessionKey);
        delete sessionKeys[sessionKey];
        emit SessionKeyRemoved(sessionKey);
    }

    function isValidSessionKey(address sessionKey) external view override returns (bool) {
        SessionKey storage key = sessionKeys[sessionKey];
        if (!key.active) {
            return false;
        }
        if (key.validUntil == 0) {
            return true;
        }
        return block.timestamp <= key.validUntil;
    }

    function addGuardian(address guardian) external override onlyOwner {
        require(guardian != address(0), "account: invalid guardian");
        require(!guardians[guardian], "account: guardian exists");
        require(guardianTotal < MAX_GUARDIANS, "account: max guardians");
        guardians[guardian] = true;
        guardianTotal += 1;
        emit GuardianAdded(guardian);
    }

    function removeGuardian(address guardian) external override onlyOwner {
        require(guardians[guardian], "account: guardian missing");
        require(guardianTotal - 1 >= RECOVERY_THRESHOLD, "account: guardian below threshold");
        guardians[guardian] = false;
        guardianTotal -= 1;
        emit GuardianRemoved(guardian);
    }

    function isGuardian(address guardian) external view override returns (bool) {
        return guardians[guardian];
    }

    function guardianCount() external view override returns (uint256) {
        return guardianTotal;
    }

    function recoveryThreshold() external pure override returns (uint256) {
        return RECOVERY_THRESHOLD;
    }

    function initiateRecovery(address newOwner) external override returns (bytes32 recoveryId) {
        require(guardians[msg.sender], "account: not guardian");
        require(guardianTotal == MAX_GUARDIANS, "account: insufficient guardians");
        require(newOwner != address(0), "account: invalid owner");

        recoveryId = keccak256(abi.encode(address(this), newOwner, recoveryNonce++));
        Recovery storage recovery = recoveries[recoveryId];
        require(recovery.newOwner == address(0), "account: recovery exists");

        recovery.newOwner = newOwner;
        recovery.executeAfter = uint48(block.timestamp + RECOVERY_TIMELOCK);
        recovery.confirmations = 1;
        recovery.executed = false;
        recoveryConfirmations[recoveryId][msg.sender] = true;

        emit RecoveryInitiated(recoveryId, newOwner, msg.sender, recovery.executeAfter);
        emit RecoveryConfirmed(recoveryId, msg.sender);
    }

    function confirmRecovery(bytes32 recoveryId) external override {
        require(guardians[msg.sender], "account: not guardian");
        Recovery storage recovery = recoveries[recoveryId];
        require(recovery.newOwner != address(0), "account: recovery missing");
        require(!recovery.executed, "account: recovery executed");
        require(!recoveryConfirmations[recoveryId][msg.sender], "account: recovery already confirmed");

        recoveryConfirmations[recoveryId][msg.sender] = true;
        recovery.confirmations += 1;
        emit RecoveryConfirmed(recoveryId, msg.sender);
    }

    function executeRecovery(bytes32 recoveryId) external override {
        Recovery storage recovery = recoveries[recoveryId];
        require(recovery.newOwner != address(0), "account: recovery missing");
        require(!recovery.executed, "account: recovery executed");
        require(recovery.confirmations >= RECOVERY_THRESHOLD, "account: insufficient confirmations");
        require(block.timestamp >= recovery.executeAfter, "account: recovery timelock");

        recovery.executed = true;
        address oldOwner = owner;
        owner = recovery.newOwner;
        emit RecoveryExecuted(recoveryId, recovery.newOwner);
        emit OwnerUpdated(oldOwner, recovery.newOwner);
    }

    function _validateSessionKeyUserOp(
        PackedUserOperation calldata userOp,
        address sessionKey
    ) internal view returns (uint256) {
        SessionKey storage key = sessionKeys[sessionKey];
        if (!key.active) {
            return SIG_VALIDATION_FAILED;
        }

        if (!_isValidExecuteCallData(userOp.callData)) {
            return SIG_VALIDATION_FAILED;
        }

        (address dest, , ) = _decodeExecuteCallData(userOp.callData);
        if (key.hasTargetList && !sessionKeyTargets[sessionKey][dest]) {
            return SIG_VALIDATION_FAILED;
        }

        uint256 callGasLimit = UserOperationLib.unpackCallGasLimit(userOp);
        if (key.gasLimit != 0 && callGasLimit > key.gasLimit) {
            return SIG_VALIDATION_FAILED;
        }

        uint48 validUntil = key.validUntil;
        if (validUntil != 0 && block.timestamp > validUntil) {
            return SIG_VALIDATION_FAILED;
        }

        return _packValidationData(false, validUntil, 0);
    }

    function _requireValidSessionKeyExecution(address sessionKey, address dest) internal view {
        SessionKey storage key = sessionKeys[sessionKey];
        require(key.active, "account: session key inactive");
        if (key.validUntil != 0) {
            require(block.timestamp <= key.validUntil, "account: session expired");
        }
        if (key.hasTargetList) {
            require(sessionKeyTargets[sessionKey][dest], "account: session target not allowed");
        }
    }

    function _isValidExecuteCallData(bytes calldata callData) internal pure returns (bool) {
        if (callData.length < 4) {
            return false;
        }
        bytes4 selector;
        assembly {
            selector := calldataload(callData.offset)
        }
        return selector == INexusAccount.execute.selector;
    }

    function _decodeExecuteCallData(
        bytes calldata callData
    ) internal pure returns (address dest, uint256 value, bytes memory func) {
        bytes calldata innerCall = callData[4:];
        return abi.decode(innerCall, (address, uint256, bytes));
    }

    function _clearSessionKeyTargets(address sessionKey) internal {
        address[] storage list = sessionKeyTargetList[sessionKey];
        for (uint256 i = 0; i < list.length; i++) {
            sessionKeyTargets[sessionKey][list[i]] = false;
        }
        delete sessionKeyTargetList[sessionKey];
    }

    function _call(address dest, uint256 value, bytes memory func) internal {
        (bool success, bytes memory result) = dest.call{value: value}(func);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
