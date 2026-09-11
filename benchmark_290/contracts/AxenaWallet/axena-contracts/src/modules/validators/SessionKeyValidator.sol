// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {ISessionKeyValidator, SessionData} from "../../interfaces/ISessionKeyValidator.sol";
import {IValidator} from "../../interfaces/IValidator.sol";
import {SessionLib} from "../../libraries/SessionLib.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";

/// @title SessionKeyValidator
/// @notice Validates ERC-4337 UserOps signed by session keys with per-key permissions.
/// @dev ERC-4337 STAKING REQUIREMENT (STO-010): This validator writes to its own storage
/// (totalSpent, agentBudgets) during the validation phase. Because these writes target
/// non-associated storage (the validator's storage, not the wallet's), this contract MUST
/// be staked with the EntryPoint per ERC-4337 specification rule STO-010. Bundlers will
/// reject UserOps from unstaked validators that access non-associated storage.
/// Call `stake(entryPoint, unstakeDelaySec)` after deployment with sufficient ETH value.
/// Production wallets (Biconomy, ZeroDev) use this same pattern.
/// @dev ERC-165 supportsInterface is intentionally omitted. Modules are trusted,
/// audited code installed by the wallet owner, so on-chain interface discovery
/// adds gas overhead without meaningful security benefit.
contract SessionKeyValidator is ISessionKeyValidator, IValidator {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct AgentTokenBudget {
        uint256 limit;
        uint256 spent;
        uint256 periodDuration;
        uint256 periodStart;
    }

    // wallet => sessionKey => SessionData
    mapping(address => mapping(address => SessionData)) private _sessions;
    // wallet => install nonce (incremented on uninstall to invalidate all sessions)
    mapping(address => uint256) private _installNonce;
    // wallet => sessionKey => nonce at creation time
    mapping(address => mapping(address => uint256)) private _sessionNonce;
    // wallet => sessionKey => token => AgentTokenBudget
    mapping(address => mapping(address => mapping(address => AgentTokenBudget))) private _agentBudgets;

    // ERC-20 function selectors
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;
    bytes4 private constant TRANSFER_FROM_SELECTOR = 0x23b872dd;
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;

    uint256 constant VALIDATION_FAILED = 1;

    error InvalidSessionKey();
    error SessionAlreadyExpired();
    error InvalidTimeRange();
    error EmptyAllowedTargets();
    error TooManyTargets();
    error TooManySelectors();
    error BudgetArrayMismatch();
    error CannotTargetWallet();
    error CannotTargetValidator();
    error CannotTargetEntryPoint();
    error DuplicateBudgetToken();
    error TooManyBudgetTokens();
    error ZeroBudgetLimit();
    error OnlyStakeOwner();

    event ModuleInstalled(address indexed wallet);
    event ModuleUninstalled(address indexed wallet);
    event Staked(address indexed entryPoint, uint256 value, uint32 unstakeDelaySec);

    /// @notice Create a new session key with permissions
    /// @param session The session data including key, targets, selectors, and limits
    function createSession(SessionData calldata session) external {
        if (session.sessionKey == address(0)) revert InvalidSessionKey();
        if (session.validUntil <= block.timestamp) revert SessionAlreadyExpired();
        if (session.validAfter >= session.validUntil) revert InvalidTimeRange();
        if (session.allowedTargets.length == 0) revert EmptyAllowedTargets();
        if (session.allowedTargets.length > 50) revert TooManyTargets();
        if (session.allowedSelectors.length > 50) revert TooManySelectors();
        // Budget arrays must be same length (or all empty)
        if (session.budgetTokens.length > 50) revert TooManyBudgetTokens();
        if (
            session.budgetTokens.length != session.budgetLimits.length
            || session.budgetTokens.length != session.budgetPeriods.length
        ) revert BudgetArrayMismatch();
        // Block session keys from targeting the wallet itself, this validator,
        // or the wallet's EntryPoint (prevents ETH extraction via depositTo)
        address ep;
        (bool epOk, bytes memory epData) = msg.sender.staticcall(
            abi.encodeWithSignature("entryPoint()")
        );
        if (epOk && epData.length >= 32) {
            ep = abi.decode(epData, (address));
        }
        for (uint256 i; i < session.allowedTargets.length;) {
            if (session.allowedTargets[i] == msg.sender) revert CannotTargetWallet();
            if (session.allowedTargets[i] == address(this)) revert CannotTargetValidator();
            if (ep != address(0) && session.allowedTargets[i] == ep) revert CannotTargetEntryPoint();
            unchecked { ++i; }
        }
        // Reject duplicate budget tokens (duplicates cause double-counting in validateUserOp)
        for (uint256 i; i < session.budgetTokens.length;) {
            for (uint256 j = i + 1; j < session.budgetTokens.length;) {
                if (session.budgetTokens[i] == session.budgetTokens[j]) revert DuplicateBudgetToken();
                unchecked { ++j; }
            }
            unchecked { ++i; }
        }
        // Clear stale agent budgets from any previous session for this key
        SessionData storage existing = _sessions[msg.sender][session.sessionKey];
        for (uint256 i; i < existing.budgetTokens.length;) {
            delete _agentBudgets[msg.sender][session.sessionKey][existing.budgetTokens[i]];
            unchecked { ++i; }
        }

        _sessions[msg.sender][session.sessionKey] = session;
        // Reset totalSpent on creation
        _sessions[msg.sender][session.sessionKey].totalSpent = 0;
        // Record current install nonce so session is invalidated on uninstall
        _sessionNonce[msg.sender][session.sessionKey] = _installNonce[msg.sender];

        // Initialize per-agent token budgets
        for (uint256 i; i < session.budgetTokens.length;) {
            if (session.budgetLimits[i] == 0) revert ZeroBudgetLimit();
            _agentBudgets[msg.sender][session.sessionKey][session.budgetTokens[i]] = AgentTokenBudget({
                limit: session.budgetLimits[i],
                spent: 0,
                periodDuration: session.budgetPeriods[i],
                periodStart: session.validAfter > block.timestamp ? session.validAfter : block.timestamp
            });
            unchecked { ++i; }
        }

        emit SessionCreated(msg.sender, session.sessionKey, session.validUntil);
    }

    /// @notice Revoke an existing session key
    /// @param sessionKey The session key address to revoke
    function revokeSession(address sessionKey) external {
        _sessions[msg.sender][sessionKey].revoked = true;
        emit SessionRevoked(msg.sender, sessionKey);
    }

    /// @notice Get session data for a wallet/key pair
    /// @param wallet The wallet address
    /// @param sessionKey The session key address
    /// @return The session data
    function getSession(address wallet, address sessionKey) external view returns (SessionData memory) {
        return _sessions[wallet][sessionKey];
    }

    /// @notice Check if a session key is currently valid
    /// @param wallet The wallet address
    /// @param sessionKey The session key address
    /// @return Whether the session is valid
    function isSessionValid(address wallet, address sessionKey) external view returns (bool) {
        SessionData storage s = _sessions[wallet][sessionKey];
        return !s.revoked
            && s.sessionKey != address(0)
            && block.timestamp >= s.validAfter
            && block.timestamp < s.validUntil
            && _sessionNonce[wallet][sessionKey] == _installNonce[wallet];
    }

    /// @notice Validate a UserOp signed by a session key
    /// @param userOp The packed user operation
    /// @param userOpHash The hash of the user operation (includes nonce + chainId)
    /// @return validationData Packed (sigFail, validUntil, validAfter) per ERC-4337 v0.7
    /// @dev NOTE: totalSpent and agentBudgets are updated during validation (ERC-4337 constraint).
    /// If the UserOp execution subsequently fails, these increments persist. This is a known
    /// ERC-4337 limitation: validation state changes are not rolled back on execution failure.
    /// Impact is limited because an attacker who has the session key could spend the budget
    /// legitimately anyway. The budget serves as a cap, not a guarantee of actual spend.
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external returns (uint256) {
        // Verify caller is the wallet that owns the session (prevents external griefing)
        if (userOp.sender != msg.sender) return VALIDATION_FAILED;

        // Signature = sessionKey signature (tryRecover avoids revert on malformed sigs per ERC-4337)
        bytes32 ethHash = userOpHash.toEthSignedMessageHash();
        (address recovered, ECDSA.RecoverError recoverErr,) = ECDSA.tryRecover(ethHash, userOp.signature);
        if (recoverErr != ECDSA.RecoverError.NoError) return VALIDATION_FAILED;

        SessionData storage session = _sessions[userOp.sender][recovered];

        // Check session exists and is valid
        if (session.sessionKey == address(0)) return VALIDATION_FAILED;
        if (session.revoked) return VALIDATION_FAILED;
        if (block.timestamp < session.validAfter || block.timestamp >= session.validUntil) return VALIDATION_FAILED;
        // Check session was created under current install nonce
        if (_sessionNonce[userOp.sender][recovered] != _installNonce[userOp.sender]) return VALIDATION_FAILED;

        // Decode the calldata to get the target, value, data from execute(address,uint256,bytes)
        // Minimum: 4 (selector) + 32 (address) + 32 (uint256) + 32 (offset) + 32 (length) = 132
        if (userOp.callData.length < 132) return VALIDATION_FAILED;

        bytes4 walletSelector = bytes4(userOp.callData[:4]);
        // execute(address,uint256,bytes) selector = 0xb61d27f6
        if (walletSelector != bytes4(0xb61d27f6)) return VALIDATION_FAILED;

        (address target, uint256 value, bytes memory data) = abi.decode(userOp.callData[4:], (address, uint256, bytes));

        // Block session keys from targeting the wallet itself (self-call escalation)
        if (target == userOp.sender) return VALIDATION_FAILED;

        // Check target allowlist
        SessionLib.Permission memory perm = SessionLib.Permission({
            allowedTargets: session.allowedTargets,
            allowedSelectors: session.allowedSelectors,
            spendLimit: session.spendLimit,
            totalSpendLimit: session.totalSpendLimit
        });

        if (!SessionLib.isTargetAllowed(perm, target)) return VALIDATION_FAILED;

        // Extract function selector once for both allowlist check and budget check (G-7)
        bytes4 fnSelector;
        if (data.length >= 4) {
            assembly {
                fnSelector := mload(add(data, 32))
            }
        }

        // Check selector allowlist
        if (data.length >= 4) {
            if (session.allowedSelectors.length > 0) {
                bool found = false;
                uint256 selectorLen = session.allowedSelectors.length < 50 ? session.allowedSelectors.length : 50;
                for (uint256 i; i < selectorLen;) {
                    if (session.allowedSelectors[i] == fnSelector) {
                        found = true;
                        break;
                    }
                    unchecked { ++i; }
                }
                if (!found) return VALIDATION_FAILED;
            }
        } else if (session.allowedSelectors.length > 0) {
            // Session has selector restrictions but call data has no selector (plain ETH transfer)
            return VALIDATION_FAILED;
        }

        // Check per-tx spend limit
        if (session.spendLimit > 0 && value > session.spendLimit) return VALIDATION_FAILED;

        // Check cumulative spend limit (read-only check first, write after all checks pass)
        if (session.totalSpendLimit > 0) {
            if (session.totalSpent + value > session.totalSpendLimit) return VALIDATION_FAILED;
        }

        // Check per-agent token budgets (if configured)
        if (session.budgetTokens.length > 0 && data.length >= 4) {
            if (fnSelector == TRANSFER_SELECTOR || fnSelector == APPROVE_SELECTOR) {
                // transfer/approve require at least 68 bytes (4 selector + 32 address + 32 uint256)
                if (data.length < 68) return VALIDATION_FAILED;
                uint256 tokenAmount = _extractTokenAmount(fnSelector, data);
                if (!_checkAgentBudget(userOp.sender, recovered, target, fnSelector, tokenAmount)) {
                    return VALIDATION_FAILED;
                }
                emit AgentSpend(userOp.sender, recovered, target, tokenAmount);
            } else if (fnSelector == TRANSFER_FROM_SELECTOR) {
                // transferFrom requires at least 100 bytes (4 selector + 32 from + 32 to + 32 uint256)
                if (data.length < 100) return VALIDATION_FAILED;
                uint256 tokenAmount = _extractTokenAmount(fnSelector, data);
                if (!_checkAgentBudget(userOp.sender, recovered, target, fnSelector, tokenAmount)) {
                    return VALIDATION_FAILED;
                }
                emit AgentSpend(userOp.sender, recovered, target, tokenAmount);
            }
        }

        // All checks passed — commit cumulative ETH spend
        if (session.totalSpendLimit > 0) {
            session.totalSpent += value;
        }

        // Return packed validationData per ERC-4337 v0.7:
        // bits 0-159: 0 (sigFail = false, no aggregator)
        // bits 160-207: validUntil (uint48)
        // bits 208-255: validAfter (uint48)
        // This allows bundlers to enforce session time windows at simulation layer,
        // preventing gas waste from including expired-session UserOps.
        return (uint256(session.validUntil) << 160) | (uint256(session.validAfter) << 208);
    }

    /// @notice Get the agent token budget for a specific wallet/key/token
    function getAgentBudget(address wallet, address sessionKey, address token)
        external view returns (AgentTokenBudget memory)
    {
        return _agentBudgets[wallet][sessionKey][token];
    }

    /// @dev Extract the token amount from ERC-20 calldata using assembly offset reads (G-6).
    /// Avoids memory allocation and copying by reading directly from the data buffer.
    function _extractTokenAmount(bytes4 selector, bytes memory data) private pure returns (uint256) {
        if (selector == TRANSFER_SELECTOR || selector == APPROVE_SELECTOR) {
            // transfer(address,uint256) or approve(address,uint256) - needs 4 + 64 bytes
            if (data.length < 68) return 0;
            // Amount is at offset 36 (4 selector + 32 address) from data start
            uint256 amount;
            assembly {
                amount := mload(add(data, 68)) // 32 (length prefix) + 4 (selector) + 32 (address) = 68
            }
            return amount;
        } else if (selector == TRANSFER_FROM_SELECTOR) {
            // transferFrom(address,address,uint256) - needs 4 + 96 bytes
            if (data.length < 100) return 0;
            // Amount is at offset 68 (4 selector + 32 from + 32 to) from data start
            uint256 amount;
            assembly {
                amount := mload(add(data, 100)) // 32 (length prefix) + 4 (selector) + 32 (from) + 32 (to) = 100
            }
            return amount;
        }
        return 0;
    }

    /// @dev Check and update per-agent token budget
    function _checkAgentBudget(
        address wallet, address agent, address token, bytes4 selector, uint256 amount
    ) private returns (bool) {
        AgentTokenBudget storage budget = _agentBudgets[wallet][agent][token];
        // No budget configured for this token = pass
        if (budget.limit == 0) return true;

        // Lazy reset: advance periodStart by whole periods (not to block.timestamp)
        // to prevent double-spending at period boundaries
        if (budget.periodDuration > 0 && block.timestamp - budget.periodStart >= budget.periodDuration) {
            uint256 elapsed = block.timestamp - budget.periodStart;
            uint256 periodsElapsed = elapsed / budget.periodDuration;
            budget.periodStart += periodsElapsed * budget.periodDuration;
            budget.spent = 0;
        }

        // Unlimited approve counts as full budget
        uint256 effectiveAmount = amount;
        if (selector == APPROVE_SELECTOR && amount == type(uint256).max) {
            effectiveAmount = budget.limit;
        }

        uint256 remaining = budget.limit > budget.spent ? budget.limit - budget.spent : 0;
        if (effectiveAmount > remaining) return false;

        budget.spent += effectiveAmount;
        return true;
    }

    /// @notice Invalidate all existing sessions when wallet ownership changes.
    /// @dev After recovery, the old (compromised) owner's session keys must not
    /// remain valid. Incrementing the install nonce makes all prior sessions fail
    /// the nonce check in validateUserOp, effectively revoking them.
    function updateOwner(address) external {
        _installNonce[msg.sender]++;
    }

    /// @notice Called when module is installed on a wallet
    function onInstall(bytes calldata) external {
        emit ModuleInstalled(msg.sender);
    }

    /// @notice Called when module is uninstalled from a wallet
    /// @dev Increments install nonce to invalidate all existing sessions
    function onUninstall() external {
        _installNonce[msg.sender]++;
        emit ModuleUninstalled(msg.sender);
    }

    // ─── ERC-4337 Staking (STO-010 compliance) ──────────────────────────

    address public immutable stakeOwner;

    constructor() {
        stakeOwner = msg.sender;
    }

    /// @notice Stake this validator with the EntryPoint (required for non-associated storage access)
    /// @dev Must be called by the deployer/owner with ETH value. The validator writes to its own
    /// storage during ERC-4337 validation, which requires staking per STO-010.
    /// Aderyn H-2 false positive: ETH cannot get stuck in this contract because msg.value is
    /// always forwarded in full to entryPoint.addStake(). Withdrawal is handled by
    /// unlockStake() + withdrawStake() which route through the EntryPoint's own withdrawal flow.
    /// @param entryPoint The ERC-4337 EntryPoint contract
    /// @param unstakeDelaySec Minimum delay (in seconds) before stake can be withdrawn
    function stake(IEntryPoint entryPoint, uint32 unstakeDelaySec) external payable {
        if (msg.sender != stakeOwner) revert OnlyStakeOwner();
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
        emit Staked(address(entryPoint), msg.value, unstakeDelaySec);
    }

    /// @notice Unlock the stake (begins the unstake delay period)
    /// @param entryPoint The ERC-4337 EntryPoint contract
    function unlockStake(IEntryPoint entryPoint) external {
        if (msg.sender != stakeOwner) revert OnlyStakeOwner();
        entryPoint.unlockStake();
    }

    /// @notice Withdraw the stake after the unstake delay has elapsed
    /// @param entryPoint The ERC-4337 EntryPoint contract
    /// @param withdrawAddress The address to receive the withdrawn stake
    function withdrawStake(IEntryPoint entryPoint, address payable withdrawAddress) external {
        if (msg.sender != stakeOwner) revert OnlyStakeOwner();
        entryPoint.withdrawStake(withdrawAddress);
    }
}
