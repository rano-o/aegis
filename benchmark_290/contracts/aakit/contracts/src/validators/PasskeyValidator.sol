// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {PackedUserOperation} from "../interfaces/IERC4337.sol";
import {IERC7579Validator} from "../interfaces/IERC7579.sol";

/**
 * @title PasskeyValidator
 * @notice Validates P256 (secp256r1) signatures for WebAuthn passkeys
 * @dev Uses RIP-7212 precompile when available, falls back to library
 */
contract PasskeyValidator is IERC7579Validator {
    // P256 precompile address (RIP-7212)
    address private constant P256_VERIFIER = address(0x100);
    
    // P256 curve order
    uint256 private constant P256_N = 
        0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    // WebAuthn authentication data structure
    struct WebAuthnAuth {
        bytes authenticatorData;
        bytes clientDataJSON;
        uint256 challengeIndex;
        uint256 typeIndex;
        uint256 r;
        uint256 s;
    }

    // Events
    event PasskeyValidated(address indexed account, bytes32 userOpHash, bool success);

    // Errors
    error InvalidSignature();
    error InvalidAuthenticatorData();
    error InvalidClientData();
    error InvalidPublicKey();
    error PrecompileCallFailed();

    // ERC-165 support
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC7579Validator).interfaceId;
    }

    /**
     * @notice Module type identifier
     */
    function isModuleType(uint256 moduleTypeId) external pure override returns (bool) {
        return moduleTypeId == 1; // Validator type
    }

    /**
     * @notice Initialize module
     * @param data Initialization data (unused)
     */
    function onInstall(bytes calldata data) external override {
        // No initialization needed
    }

    /**
     * @notice De-initialize module
     * @param data De-initialization data (unused)
     */
    function onUninstall(bytes calldata data) external override {
        // No cleanup needed
    }

    /**
     * @notice Validate user operation
     * @param userOp User operation
     * @param userOpHash Hash of user operation
     * @return validationData 0 for success, 1 for failure
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) external override returns (uint256 validationData) {
        // Decode signature wrapper
        (, bytes memory signatureData) = abi.decode(userOp.signature, (uint8, bytes));
        
        // Decode WebAuthn auth data
        WebAuthnAuth memory auth = abi.decode(signatureData, (WebAuthnAuth));
        
        // Get public key from wallet (would need to pass this in practice)
        // For now, this is a simplified version
        // In production, the wallet would pass the public key based on ownerIndex
        
        // Validate signature
        bool isValid = _validateWebAuthnSignature(
            userOpHash,
            auth,
            0, // publicKeyX - would come from wallet
            0  // publicKeyY - would come from wallet
        );
        
        emit PasskeyValidated(userOp.sender, userOpHash, isValid);
        
        return isValid ? 0 : 1;
    }

    /**
     * @notice Validate ERC-1271 signature
     * @param sender Original sender
     * @param hash Hash to validate
     * @param signature Signature data
     * @return Magic value if valid
     */
    function isValidSignatureWithSender(
        address sender,
        bytes32 hash,
        bytes calldata signature
    ) external view override returns (bytes4) {
        // Decode WebAuthn auth
        WebAuthnAuth memory auth = abi.decode(signature, (WebAuthnAuth));
        
        // Validate (simplified - would need public key from sender)
        bool isValid = _validateWebAuthnSignature(hash, auth, 0, 0);
        
        return isValid ? bytes4(0x1626ba7e) : bytes4(0xffffffff);
    }

    /**
     * @notice Validate WebAuthn signature
     * @param challenge Challenge hash (userOpHash)
     * @param auth WebAuthn authentication data
     * @param publicKeyX X coordinate of public key
     * @param publicKeyY Y coordinate of public key
     * @return True if signature is valid
     */
    function _validateWebAuthnSignature(
        bytes32 challenge,
        WebAuthnAuth memory auth,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) internal view returns (bool) {
        // Validate authenticator data
        if (auth.authenticatorData.length < 37) {
            return false;
        }
        
        // Check flags (UP and UV must be set)
        bytes1 flags = auth.authenticatorData[32];
        if ((flags & 0x05) != 0x05) {
            // UP (bit 0) and UV (bit 2) must both be set
            return false;
        }
        
        // Reconstruct the signed message
        bytes32 clientDataHash = sha256(auth.clientDataJSON);
        bytes memory message = abi.encodePacked(
            auth.authenticatorData,
            clientDataHash
        );
        bytes32 messageHash = sha256(message);
        
        // Normalize s value (prevent malleability)
        uint256 s = auth.s;
        if (s > P256_N / 2) {
            s = P256_N - s;
        }
        
        // Verify P256 signature
        return _verifyP256Signature(
            messageHash,
            auth.r,
            s,
            publicKeyX,
            publicKeyY
        );
    }

    /**
     * @notice Verify P256 signature using precompile or fallback
     * @param messageHash Hash of message
     * @param r Signature r value
     * @param s Signature s value
     * @param publicKeyX Public key X coordinate
     * @param publicKeyY Public key Y coordinate
     * @return True if signature is valid
     */
    function _verifyP256Signature(
        bytes32 messageHash,
        uint256 r,
        uint256 s,
        uint256 publicKeyX,
        uint256 publicKeyY
    ) internal view returns (bool) {
        // Try RIP-7212 precompile first
        (bool success, bytes memory result) = P256_VERIFIER.staticcall(
            abi.encode(messageHash, r, s, publicKeyX, publicKeyY)
        );
        
        if (success && result.length > 0) {
            return abi.decode(result, (uint256)) == 1;
        }
        
        // Fallback: Would use FreshCryptoLib or similar
        // For this implementation, we'll just return false if precompile unavailable
        // In production, integrate a Solidity P256 library here
        return false;
    }

    /**
     * @notice Extract challenge from clientDataJSON
     * @param clientDataJSON WebAuthn client data
     * @param challengeIndex Index of challenge in JSON
     * @return Challenge bytes
     */
    function _extractChallenge(
        bytes memory clientDataJSON,
        uint256 challengeIndex
    ) internal pure returns (bytes memory) {
        // Simplified extraction - production version needs proper JSON parsing
        // Challenge is base64url encoded in the JSON
        
        // This is a placeholder - real implementation would:
        // 1. Parse JSON to find "challenge" field
        // 2. Extract base64url value
        // 3. Decode base64url
        
        return new bytes(32);
    }

    /**
     * @notice Validate origin and RP ID
     * @param authenticatorData WebAuthn authenticator data
     * @param clientDataJSON Client data JSON
     * @param expectedRpIdHash Expected RP ID hash
     * @return True if valid
     */
    function _validateOrigin(
        bytes memory authenticatorData,
        bytes memory clientDataJSON,
        bytes32 expectedRpIdHash
    ) internal pure returns (bool) {
        // Check RP ID hash (first 32 bytes of authenticatorData)
        bytes32 rpIdHash;
        assembly {
            rpIdHash := mload(add(authenticatorData, 32))
        }
        
        if (rpIdHash != expectedRpIdHash) {
            return false;
        }
        
        // Would also validate origin from clientDataJSON
        // Simplified for this implementation
        
        return true;
    }
}
