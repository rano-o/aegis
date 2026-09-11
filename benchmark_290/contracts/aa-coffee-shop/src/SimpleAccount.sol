// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import "lib/openzeppelin-contracts/contracts/proxy/utils/Initializable.sol";
import "./interfaces/IERC4337.sol";

/**
 * @title SimpleAccount
 * @dev ERC-4337 compliant smart contract account with single owner
 * 
 * This contract implements a simple account abstraction wallet that:
 * - Has a single owner who can authorize operations
 * - Can execute arbitrary transactions via UserOperations
 * - Validates signatures using ECDSA
 * - Manages gas deposits for account abstraction
 * 
 * Flow:
 * 1. User creates UserOperation with callData for target contract
 * 2. User signs the UserOperation hash with their private key
 * 3. Bundler submits UserOperation to EntryPoint
 * 4. EntryPoint calls validateUserOp() to verify signature
 * 5. If valid, EntryPoint calls execute() to perform the operation
 */
contract SimpleAccount is IAccount, Initializable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // EntryPoint contract address (immutable for gas optimization)
    IEntryPoint private immutable _entryPoint;
    
    // Owner of this account who can authorize operations
    address public owner;

    // Events for tracking account operations
    event SimpleAccountInitialized(IEntryPoint indexed entryPoint, address indexed owner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Modifier to ensure only EntryPoint or owner can call
     * This allows both traditional transactions (from owner) and
     * account abstraction UserOperations (from EntryPoint)
     */
    modifier onlyOwnerOrEntryPoint() {
        _requireFromEntryPointOrOwner();
        _;
    }

    /**
     * @dev Constructor sets the EntryPoint address immutably
     * @param anEntryPoint The ERC-4337 EntryPoint contract
     */
    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers(); // Prevent initialization of implementation
    }

    /**
     * @dev Initializes the account with an owner
     * @param anOwner The initial owner of this account
     */
    function initialize(address anOwner) public virtual initializer {
        _initialize(anOwner);
    }

    function _initialize(address anOwner) internal virtual {
        owner = anOwner;
        emit SimpleAccountInitialized(_entryPoint, anOwner);
    }

    /**
     * @dev Validates a UserOperation signature and pays for gas if needed
     * Called by EntryPoint during UserOperation processing
     * 
     * @param userOp The UserOperation to validate
     * @param userOpHash Keccak256 hash of the UserOperation
     * @param missingAccountFunds Amount needed to pay for gas
     * @return validationData 0 for success, 1 for signature failure
     */
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external virtual override returns (uint256 validationData) {
        // Only EntryPoint can call this function
        _requireFromEntryPoint();
        
        // Validate the signature
        validationData = _validateSignature(userOp, userOpHash);
        
        // Pay for gas if account has insufficient funds
        _payPrefund(missingAccountFunds);
    }

    /**
     * @dev Executes a transaction from this account
     * Can be called directly by owner or via EntryPoint from UserOperation
     * 
     * @param dest Target contract address
     * @param value ETH value to send
     * @param func Calldata for the target function
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata func
    ) external onlyOwnerOrEntryPoint {
        _call(dest, value, func);
    }

    /**
     * @dev Executes multiple transactions in a batch
     * Useful for atomic operations like approve + transfer
     * 
     * @param dest Array of target addresses
     * @param value Array of ETH values
     * @param func Array of calldata
     */
    function executeBatch(
        address[] calldata dest,
        uint256[] calldata value,
        bytes[] calldata func
    ) external onlyOwnerOrEntryPoint {
        require(dest.length == func.length && dest.length == value.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], value[i], func[i]);
        }
    }

    /**
     * @dev Transfers ownership of the account
     * @param newOwner The new owner address
     */
    function transferOwnership(address newOwner) external onlyOwnerOrEntryPoint {
        require(newOwner != address(0), "new owner is the zero address");
        address oldOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }

    /**
     * @dev Gets the current EntryPoint
     * @return The EntryPoint contract address
     */
    function entryPoint() public view virtual returns (IEntryPoint) {
        return _entryPoint;
    }

    /**
     * @dev Gets the account's deposit in the EntryPoint
     * @return The current deposit balance
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /**
     * @dev Deposits ETH to the EntryPoint for gas payments
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value: msg.value}(address(this));
    }

    /**
     * @dev Withdraws deposit from EntryPoint
     * @param withdrawAddress Address to receive the funds
     * @param amount Amount to withdraw
     */
    function withdrawDepositTo(
        address payable withdrawAddress,
        uint256 amount
    ) public onlyOwnerOrEntryPoint {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * @dev Internal function to validate UserOperation signature
     * @param userOp The UserOperation to validate
     * @param userOpHash Hash of the UserOperation
     * @return validationData 0 for valid signature, 1 for invalid
     */
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal virtual view returns (uint256 validationData) {
        // Convert hash to Ethereum signed message format
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        
        // Recover signer from signature
        address recovered = hash.recover(userOp.signature);
        
        // Return 0 if signature is valid, 1 if invalid
        return recovered == owner ? 0 : 1;
    }

    /**
     * @dev Internal function to pay for UserOperation gas
     * @param missingAccountFunds Amount needed for gas payment
     */
    function _payPrefund(uint256 missingAccountFunds) internal virtual {
        if (missingAccountFunds != 0) {
            // Transfer ETH to EntryPoint to cover gas costs
            (bool success,) = payable(msg.sender).call{value: missingAccountFunds}("");
            require(success, "failed to pay prefund");
        }
    }

    /**
     * @dev Internal function to execute a call with proper error handling
     * @param target Target contract address
     * @param value ETH value to send  
     * @param data Calldata for the call
     */
    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            // Properly forward the revert reason
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    /**
     * @dev Internal function to ensure caller is EntryPoint or owner
     */
    function _requireFromEntryPointOrOwner() internal view {
        require(
            msg.sender == address(_entryPoint) || msg.sender == owner,
            "account: not Owner or EntryPoint"
        );
    }

    /**
     * @dev Internal function to ensure caller is EntryPoint
     */
    function _requireFromEntryPoint() internal view {
        require(msg.sender == address(_entryPoint), "account: not from EntryPoint");
    }

    /**
     * @dev Allows the account to receive ETH
     */
    receive() external payable {}
}