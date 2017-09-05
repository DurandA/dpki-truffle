pragma solidity ^0.4.15;

contract DPKI {
    struct Signer {
        address revocationKey;
        Signature[] signatures;
    }

    struct Signature {
        address key;
        uint expiry;
        address revocationKey;
    }

    mapping (address => Signer) public keys;

    address[] public revokedKeys;
    mapping (address => address[]) public revokedSignatures;

    event SignatureAdded(address indexed signer, address indexed signedKey);
    event SignatureRevoked(address indexed signer, address indexed signedKey);
    event KeyRevoked(address indexed key);

    function signKey(address key, uint expiry) {
        keys[msg.sender].signatures.push(Signature(key, expiry, 0x00))/*<--*/;
        SignatureAdded(msg.sender, key);
    }

    function revokeSignature(address signedKey) {
        revokedSignatures[msg.sender].push(signedKey);
        SignatureRevoked(msg.sender, signedKey);
    }

    function revokeKey() {
        revokedKeys.push(msg.sender);
        KeyRevoked(msg.sender);
    }

    function revokeKey(address key) {
        require(msg.sender == keys[key].revocationKey);

        revokedKeys.push(key);
        KeyRevoked(key);
    }
}
