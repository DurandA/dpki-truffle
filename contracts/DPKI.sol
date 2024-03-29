pragma solidity ^0.4.15;

contract DPKI {
    struct Signer {
        address revocationKey;
        uint certBlockHash; /* IPFS certificate block hash stored in 32 bytes
                               see https://ethereum.stackexchange.com/a/6862
                            */
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

    function getSignature(address signer, uint index) public constant returns(address, uint) {
        var signature = keys[signer].signatures[index];
        return (signature.key, signature.expiry);
    }

    function getSignaturesLength(address signer) public constant returns(uint) {
        return keys[signer].signatures.length;
    }

    function publish(uint certBlockHash, address revocationKey) {
        require (keys[msg.sender].certBlockHash == 0);
        require (keys[msg.sender].revocationKey == 0);

        keys[msg.sender].certBlockHash = certBlockHash;
        keys[msg.sender].revocationKey = revocationKey;
    }

    function signKey(address key, uint expiry) public returns(address) {
        keys[msg.sender].signatures.push(Signature(key, expiry, 0x00))/*<--*/;
        SignatureAdded(msg.sender, key);
        return key;
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
