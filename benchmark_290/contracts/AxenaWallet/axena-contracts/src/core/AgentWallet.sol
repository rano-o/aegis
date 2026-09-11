// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IAccount} from "@account-abstraction/interfaces/IAccount.sol";
import {PackedUserOperation} from "@account-abstraction/interfaces/PackedUserOperation.sol";
import {IEntryPoint} from "@account-abstraction/interfaces/IEntryPoint.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {ModuleManager} from "./ModuleManager.sol";
import {IAgentWallet} from "../interfaces/IAgentWallet.sol";
import {ExecutionLib} from "../libraries/ExecutionLib.sol";
import {IValidator} from "../interfaces/IValidator.sol";

contract AgentWallet is IAccount, IAgentWallet, IERC1271, ModuleManager, UUPSUpgradeable, Initializable {
    IEntryPoint public immutable entryPoint;

    // ─── ERC-7201 Namespaced Storage ─────────────────────
    // Slot derivation (ERC-7201):
    //   keccak256(abi.encode(uint256(keccak256("agentwallet.storage.AgentWallet")) - 1)) & ~bytes32(uint256(0xff))
    // Verify: cast keccak "agentwallet.storage.AgentWallet" → subtract 1 → abi.encode → keccak → mask low byte
    bytes32 private constant AGENT_WALLET_STORAGE_LOCATION =
        0x5d4aa496d924cfbf389e631bd0636c52234df5fc0e03ef70eea09b0ddb7d2100;

    /// @custom:storage-location erc7201:agentwallet.storage.AgentWallet
    struct AgentWalletStorage {
        address owner;
        uint256 reentrancyStatus; // 1 = not entered, 2 = entered
        address feeCollector;     // Protocol fee recipient
        uint16 feeBps;            // Fee in basis points (e.g., 30 = 0.30%)
        address factory;          // Factory that created this wallet (controls fee config)
    }

    function _getAgentWalletStorage() private pure returns (AgentWalletStorage storage s) {
        bytes32 slot = AGENT_WALLET_STORAGE_LOCATION;
        assembly {
            s.slot := slot
        }
    }

    // ERC-4337 validation failure sentinel
    uint256 constant VALIDATION_FAILED = 1;

    // ERC-1271
    bytes4 constant ERC1271_SUCCESS = 0x1626ba7e;

    uint16 public constant MAX_FEE_BPS = 30; // Hard cap: 0.3%
    uint256 public constant MAX_BATCH_SIZE = 64;

    // Pre-computed selectors for lifecycle functions (gas optimization: avoids runtime keccak256)
    bytes4 private constant SELECTOR_ON_INSTALL = 0x6d61fe70;   // bytes4(keccak256("onInstall(bytes)"))
    bytes4 private constant SELECTOR_ON_UNINSTALL = 0x8de2de52; // bytes4(keccak256("onUninstall()"))
    bytes4 private constant SELECTOR_UPDATE_OWNER = 0x880cdc31; // bytes4(keccak256("updateOwner(address)"))


    error OnlyOwner();
    error OnlyEntryPoint();
    error OnlyEntryPointOrOwner();
    error OnlyFactory();
    error OnlyExecutorModule();
    error HookCallFailed();
    error HookRejected();
    error ReentrancyGuardReentrantCall();
    error SelfCallNotAllowed();
    error ModuleCallNotAllowed();
    error FeeTooHigh();
    error UpgradeBlockedByDeveloperFreeze();
    error OwnerCannotBeZeroAddress();
    error ArrayLengthMismatch();
    error NewOwnerIsZeroAddress();
    error NewOwnerIsWallet();
    error LifecycleSelectorBlocked();
    error InvalidCalldata();
    error ModuleCallFailed();
    error EntryPointMismatch();
    error BatchTooLarge();
    error FeeCollectorZeroAddress();

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ValidatorUpdateOwnerFailed(address indexed validator, address indexed newOwner, bytes returnData);
    event ModuleConfigured(address indexed module, bytes data);

    modifier onlyOwner() {
        if (msg.sender != _getAgentWalletStorage().owner) revert OnlyOwner();
        _;
    }

    modifier onlyEntryPoint() {
        if (msg.sender != address(entryPoint)) revert OnlyEntryPoint();
        _;
    }

    modifier onlyEntryPointOrOwner() {
        if (msg.sender != address(entryPoint) && msg.sender != _getAgentWalletStorage().owner)
            revert OnlyEntryPointOrOwner();
        _;
    }

    modifier onlyOwnerOrSelf() override {
        if (msg.sender != _getAgentWalletStorage().owner && msg.sender != address(this)) revert OnlyOwner();
        _;
    }

    modifier nonReentrant() {
        AgentWalletStorage storage s = _getAgentWalletStorage();
        if (s.reentrancyStatus != 1) revert ReentrancyGuardReentrantCall();
        s.reentrancyStatus = 2;
        _;
        s.reentrancyStatus = 1;
    }

    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
        _disableInitializers();
    }

    /// @notice Initialize the wallet with an owner address and protocol fee config
    /// @param ownerAddr The initial owner of the wallet
    /// @param _feeCollector Protocol fee recipient address
    /// @param _feeBps Fee in basis points (max 30 = 0.3%)
    function initialize(address ownerAddr, address _feeCollector, uint16 _feeBps) external initializer {
        if (ownerAddr == address(0)) revert OwnerCannotBeZeroAddress();
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        if (_feeBps > 0 && _feeCollector == address(0)) revert FeeCollectorZeroAddress();
        AgentWalletStorage storage s = _getAgentWalletStorage();
        s.owner = ownerAddr;
        s.reentrancyStatus = 1;
        s.feeCollector = _feeCollector;
        s.feeBps = _feeBps;
        s.factory = msg.sender;
        emit OwnershipTransferred(address(0), ownerAddr);
    }

    // ─── IAccount ────────────────────────────────────
    /// @inheritdoc IAccount
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external onlyEntryPoint returns (uint256 validationData) {
        // Pay prefund to EntryPoint (safe: return value intentionally ignored per ERC-4337)
        if (missingAccountFunds > 0) {
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}(""); // safe: EntryPoint prefund
            (success); // ignore failure (EntryPoint will revert if needed)
        }

        // Route to validator based on nonce key (high 192 bits)
        // nonceKey maps directly to validator array index: 0 → validators[0], 1 → validators[1], etc.
        uint192 nonceKey = uint192(userOp.nonce >> 64);
        address[] memory validators = _getModules(ModuleType.Validator);

        if (nonceKey < validators.length) {
            (bool success, bytes memory result) = validators[nonceKey].call(
                abi.encodeWithSelector(
                    IValidator.validateUserOp.selector,
                    userOp, userOpHash
                )
            );
            if (success && result.length >= 32) {
                return abi.decode(result, (uint256));
            }
            return VALIDATION_FAILED;
        }

        return VALIDATION_FAILED;
    }

    // ─── Execution ───────────────────────────────────
    /// @notice Execute a single transaction through the wallet
    /// @param target The target contract address
    /// @param value The ETH value to send
    /// @param data The calldata to execute
    function execute(address target, uint256 value, bytes calldata data) external payable nonReentrant onlyEntryPointOrOwner returns (bytes memory result) {
        if (target == address(this)) revert SelfCallNotAllowed();
        _requireNotInstalledModule(target);
        // Cache hooks once to avoid loading from storage twice
        address[] memory hooks = _getModules(ModuleType.Hook);
        // Hooks see the original (pre-fee) value for accurate spend tracking
        _beforeExecution(hooks, target, value, data);
        uint256 netValue = _deductFee(value);
        result = ExecutionLib.execute(target, netValue, data);
        _afterExecution(hooks, target, value, data);
        emit Executed(target, netValue, data);
    }

    /// @notice Execute a batch of transactions through the wallet
    /// @param targets The target contract addresses
    /// @param values The ETH values to send
    /// @param datas The calldata to execute
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable nonReentrant onlyEntryPointOrOwner returns (bytes[] memory results) {
        if (targets.length != values.length || targets.length != datas.length) revert ArrayLengthMismatch();
        if (targets.length > MAX_BATCH_SIZE) revert BatchTooLarge();
        results = new bytes[](targets.length);
        // Cache hooks once before the loop to avoid 2*N storage loads
        address[] memory hooks = _getModules(ModuleType.Hook);
        for (uint256 i; i < targets.length;) {
            if (targets[i] == address(this)) revert SelfCallNotAllowed();
            _requireNotInstalledModule(targets[i]);
            // Hooks see the original (pre-fee) value for accurate spend tracking
            _beforeExecution(hooks, targets[i], values[i], datas[i]);
            uint256 netValue = _deductFee(values[i]);
            results[i] = ExecutionLib.execute(targets[i], netValue, datas[i]);
            _afterExecution(hooks, targets[i], values[i], datas[i]);
            emit Executed(targets[i], netValue, datas[i]);
            unchecked { ++i; }
        }
    }

    // ─── Module Management ───────────────────────────
    /// @notice Install a module on this wallet
    /// @param moduleType The type of module to install
    /// @param module The module contract address
    /// @param initData Initialization data for the module
    function installModule(ModuleType moduleType, address module, bytes calldata initData) external nonReentrant onlyOwnerOrSelf {
        _requireNotDeveloperFrozen();
        _installModule(moduleType, module, initData);
    }

    /// @notice Uninstall a module from this wallet
    /// @dev For hooks: excludes the hook being removed from the developer freeze check.
    /// This prevents a rogue hook (one that falsely returns isFrozenByDeveloper = true)
    /// from permanently bricking wallet governance via circular dependency. Legitimate
    /// hooks (like CircuitBreakerHook) self-protect in their own onUninstall().
    /// @param moduleType The type of module to uninstall
    /// @param module The module contract address
    function uninstallModule(ModuleType moduleType, address module) external nonReentrant onlyOwnerOrSelf {
        if (moduleType == ModuleType.Hook) {
            _requireNotDeveloperFrozenExcluding(module);
        } else {
            _requireNotDeveloperFrozen();
        }
        _uninstallModule(moduleType, module);
    }

    /// @notice Call an installed module directly without running hooks.
    /// Used for admin configuration (e.g., setSpendPolicy, createSession) that must
    /// bypass hooks to avoid deadlocks while preserving msg.sender == wallet.
    /// @dev Modules are trusted code installed by the owner and must be audited before
    /// installation. Unlimited gas is acceptable by design since only installed modules
    /// can be called, and the owner is responsible for vetting module code.
    /// @param module The module contract address (must be installed)
    /// @param data The calldata to forward to the module
    function configureModule(address module, bytes calldata data) external nonReentrant onlyOwnerOrSelf {
        _requireNotDeveloperFrozen();
        if (
            !_isModuleInstalled(ModuleType.Hook, module) &&
            !_isModuleInstalled(ModuleType.Validator, module) &&
            !_isModuleInstalled(ModuleType.Executor, module)
        ) revert ModuleNotInstalled(module);
        // Require valid function call (at least 4 bytes for selector)
        if (data.length < 4) revert InvalidCalldata();
        // Block lifecycle and privileged selectors to prevent state corruption
        bytes4 selector = bytes4(data[:4]);
        if (
            selector == SELECTOR_ON_INSTALL ||
            selector == SELECTOR_ON_UNINSTALL ||
            selector == SELECTOR_UPDATE_OWNER
        ) revert LifecycleSelectorBlocked();
        (bool success, bytes memory returnData) = module.call(data);
        if (!success) {
            if (returnData.length > 0) {
                assembly { revert(add(returnData, 32), mload(returnData)) }
            }
            revert ModuleCallFailed();
        }
        emit ModuleConfigured(module, data);
    }

    /// @notice Check if a module is installed
    /// @param moduleType The type of module to check
    /// @param module The module contract address
    /// @return Whether the module is installed
    function isModuleInstalled(ModuleType moduleType, address module) external view returns (bool) {
        return _isModuleInstalled(moduleType, module);
    }

    // ─── ERC-1271 ────────────────────────────────────
    /// @notice Validate a signature per ERC-1271
    /// @param hash The hash that was signed
    /// @param signature The signature to validate
    /// @return magicValue ERC-1271 magic value if valid
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue) {
        address[] memory validators = _getModules(ModuleType.Validator);
        for (uint256 i; i < validators.length;) {
            (bool success, bytes memory result) = validators[i].staticcall(
                abi.encodeWithSignature("isValidSignature(bytes32,bytes)", hash, signature)
            );
            if (success && result.length >= 32) {
                bytes4 returnVal = abi.decode(result, (bytes4));
                if (returnVal == ERC1271_SUCCESS) return ERC1271_SUCCESS;
            }
            unchecked { ++i; }
        }
        return bytes4(0xffffffff);
    }

    // ─── Protocol Fee ─────────────────────────────────
    /// @notice Deduct protocol fee from value. Returns net value after fee.
    /// @dev Non-reverting: if fee transfer fails, the full value passes through
    /// and a FeeTransferSkipped event is emitted. This prevents a broken fee
    /// collector from bricking all wallets.
    /// A minimum fee of 1 wei is enforced when feeBps > 0 and value > 0. This
    /// prevents dust-splitting evasion where an attacker splits a large transfer
    /// into many sub-wei-fee micro-transactions to avoid paying any fee at all.
    function _deductFee(uint256 value) internal returns (uint256) {
        if (value == 0) return 0;
        AgentWalletStorage storage s = _getAgentWalletStorage();
        if (s.feeBps == 0 || s.feeCollector == address(0)) return value;
        uint256 fee = (value * s.feeBps) / 10_000;
        if (fee == 0) fee = 1; // Minimum 1 wei fee prevents dust-splitting evasion
        // Gas-limited to prevent a malicious fee collector from consuming all
        // remaining gas (EIP-150 63/64 rule). 10_000 gas is sufficient for EOA
        // receive or a simple contract fallback, but caps griefing damage.
        (bool ok,) = s.feeCollector.call{value: fee, gas: 10_000}("");
        if (!ok) {
            emit FeeTransferSkipped(s.feeCollector, fee);
            return value; // Skip fee — don't brick the user's transaction
        }
        emit FeePaid(s.feeCollector, fee);
        return value - fee;
    }

    /// @notice Update protocol fee config (callable only by the factory that created this wallet)
    /// @param _feeCollector New fee recipient
    /// @param _feeBps New fee in basis points
    function setFeeConfig(address _feeCollector, uint16 _feeBps) external {
        AgentWalletStorage storage s = _getAgentWalletStorage();
        if (msg.sender != s.factory) revert OnlyFactory();
        if (_feeBps > MAX_FEE_BPS) revert FeeTooHigh();
        if (_feeBps > 0 && _feeCollector == address(0)) revert FeeCollectorZeroAddress();
        s.feeCollector = _feeCollector;
        s.feeBps = _feeBps;
        emit FeeConfigUpdated(_feeCollector, _feeBps);
    }

    /// @notice Returns the current fee collector address
    function feeCollector() external view returns (address) {
        return _getAgentWalletStorage().feeCollector;
    }

    /// @notice Returns the current fee in basis points
    function feeBps() external view returns (uint16) {
        return _getAgentWalletStorage().feeBps;
    }

    // ─── Hook execution ──────────────────────────────
    function _beforeExecution(address[] memory hooks, address target, uint256 value, bytes calldata data) internal {
        for (uint256 i; i < hooks.length;) {
            (bool success, bytes memory result) = hooks[i].call(
                abi.encodeWithSignature("beforeExecution(address,address,uint256,bytes)", msg.sender, target, value, data)
            );
            if (!success) {
                // Bubble up the hook's revert reason for diagnosability in multi-hook setups
                if (result.length > 0) {
                    assembly { revert(add(result, 32), mload(result)) }
                }
                revert HookCallFailed();
            }
            if (result.length < 32) revert HookCallFailed();
            bool allowed = abi.decode(result, (bool));
            if (!allowed) revert HookRejected();
            unchecked { ++i; }
        }
    }

    function _afterExecution(address[] memory hooks, address target, uint256 value, bytes calldata data) internal {
        for (uint256 i; i < hooks.length;) {
            (bool success, bytes memory result) = hooks[i].call(
                abi.encodeWithSignature("afterExecution(address,address,uint256,bytes)", msg.sender, target, value, data)
            );
            if (!success) {
                if (result.length > 0) {
                    assembly { revert(add(result, 32), mload(result)) }
                }
                revert HookCallFailed();
            }
            unchecked { ++i; }
        }
    }

    // ─── Ownership ──────────────────────────────────
    /// @notice Transfer wallet ownership (callable by owner or installed executor modules)
    /// @param newOwner The new owner address
    function transferOwnership(address newOwner) external nonReentrant {
        if (newOwner == address(0)) revert NewOwnerIsZeroAddress();
        if (newOwner == address(this)) revert NewOwnerIsWallet();
        // Only owner or installed executor modules can transfer ownership
        AgentWalletStorage storage s = _getAgentWalletStorage();
        if (msg.sender != s.owner && !_isModuleInstalled(ModuleType.Executor, msg.sender)) {
            revert OnlyExecutorModule();
        }
        // Block owner-initiated transfers during developer freeze.
        // Executor modules (e.g., RecoveryExecutor) are exempt — recovery must
        // work even during a freeze to allow guardians to rescue the wallet.
        if (msg.sender == s.owner) {
            _requireNotDeveloperFrozen();
        }
        address oldOwner = s.owner;
        s.owner = newOwner;

        // Sync validators: update owner in all installed validators.
        // Failures are non-reverting to prevent a malicious validator from
        // permanently blocking ownership transfer (especially recovery).
        // Stale validator state is preferable to a permanently bricked wallet.
        address[] memory validators = _getModules(ModuleType.Validator);
        for (uint256 i; i < validators.length;) {
            (bool success, bytes memory returndata) = validators[i].call{gas: 50_000}(
                abi.encodeWithSignature("updateOwner(address)", newOwner)
            );
            if (!success) {
                emit ValidatorUpdateOwnerFailed(validators[i], newOwner, returndata);
            }
            unchecked { ++i; }
        }

        emit OwnershipTransferred(oldOwner, newOwner);
    }

    // ─── Views ───────────────────────────────────────
    /// @notice Returns the wallet owner
    /// @return The owner address
    function owner() external view returns (address) {
        return _getAgentWalletStorage().owner;
    }

    // ─── Developer Freeze Guard ─────────────────────
    /// @dev Reverts if any installed hook has an active developer freeze on this wallet.
    /// Called by privileged functions (upgrade, configureModule, installModule,
    /// transferOwnership) to prevent a compromised owner from escaping or
    /// undermining a developer-imposed emergency freeze.
    function _requireNotDeveloperFrozen() internal view {
        address[] memory hooks = _getModules(ModuleType.Hook);
        for (uint256 i; i < hooks.length;) {
            (bool success, bytes memory result) = hooks[i].staticcall(
                abi.encodeWithSignature("isFrozenByDeveloper(address)", address(this))
            );
            if (success && result.length >= 32 && abi.decode(result, (bool))) {
                revert UpgradeBlockedByDeveloperFreeze();
            }
            unchecked { ++i; }
        }
    }

    /// @dev Same as _requireNotDeveloperFrozen but skips a specific hook.
    /// Used by uninstallModule to avoid circular dependency where a rogue hook
    /// that falsely reports a developer freeze blocks its own removal.
    function _requireNotDeveloperFrozenExcluding(address excludeHook) internal view {
        address[] memory hooks = _getModules(ModuleType.Hook);
        for (uint256 i; i < hooks.length;) {
            if (hooks[i] != excludeHook) {
                (bool success, bytes memory result) = hooks[i].staticcall(
                    abi.encodeWithSignature("isFrozenByDeveloper(address)", address(this))
                );
                if (success && result.length >= 32 && abi.decode(result, (bool))) {
                    revert UpgradeBlockedByDeveloperFreeze();
                }
            }
            unchecked { ++i; }
        }
    }

    // ─── Module Target Guard ────────────────────────
    /// @dev Reverts if the target is an installed module (Validator, Hook, or Executor).
    /// All module interactions must go through configureModule() which has lifecycle
    /// selector blocking, developer freeze checks, and owner-only access control.
    /// Without this guard, execute() could be used to call onInstall/onUninstall
    /// directly on modules (bypassing ModuleManager tracking), or to call privileged
    /// functions like updateOwner() on validators via session keys through the EntryPoint.
    function _requireNotInstalledModule(address target) internal view {
        if (
            _isModuleInstalled(ModuleType.Validator, target) ||
            _isModuleInstalled(ModuleType.Hook, target) ||
            _isModuleInstalled(ModuleType.Executor, target)
        ) revert ModuleCallNotAllowed();
    }

    // ─── UUPS ────────────────────────────────────────
    /// @dev Verifies the new implementation uses the same EntryPoint to prevent
    /// silently breaking all ERC-4337 operations after upgrade. The entryPoint
    /// immutable is stored in implementation bytecode, not proxy storage, so
    /// upgrading to an implementation with a different EntryPoint would cause
    /// validateUserOp to check the wrong address (AX-22).
    function _authorizeUpgrade(address newImplementation) internal override onlyOwner {
        _requireNotDeveloperFrozen();
        (bool success, bytes memory result) = newImplementation.staticcall(
            abi.encodeWithSignature("entryPoint()")
        );
        if (!success || result.length < 32 || abi.decode(result, (address)) != address(entryPoint)) {
            revert EntryPointMismatch();
        }
    }

    // ─── EntryPoint Deposit Management ───────────────
    /// @notice Pre-fund the EntryPoint deposit for gas-efficient UserOp execution
    function addDeposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /// @notice Get this wallet's current deposit balance on the EntryPoint
    function getDeposit() external view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /// @notice Withdraw deposit from EntryPoint back to a target address
    /// @dev Blocked during developer freeze to prevent a compromised owner from
    /// draining the EntryPoint deposit, which would break UserOp execution.
    /// @param target The address to receive the withdrawn ETH
    /// @param amount The amount to withdraw
    function withdrawDepositTo(address payable target, uint256 amount) external onlyOwner {
        _requireNotDeveloperFrozen();
        entryPoint.withdrawTo(target, amount);
    }

    // ─── ERC-165 ─────────────────────────────────────
    /// @notice ERC-165 interface support (required by ERC-1155 Receiver spec)
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7 // ERC-165
            || interfaceId == 0x19822f7c // IAccount (ERC-4337)
            || interfaceId == 0x1626ba7e // ERC-1271 (isValidSignature)
            || interfaceId == 0x150b7a02 // ERC-721 Receiver
            || interfaceId == 0x4e2312e0; // ERC-1155 Receiver
    }

    // ─── Receive ETH ─────────────────────────────────
    receive() external payable {}

    // ─── ERC-721 / ERC-1155 Receiver ────────────────
    /// @notice Handle the receipt of an ERC-721 NFT (safeTransferFrom)
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }

    /// @notice Handle the receipt of a single ERC-1155 token
    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    /// @notice Handle the receipt of a batch of ERC-1155 tokens
    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }
}
