var libSodiumWrapper = require("libsodium-wrappers");
var tweetnaclUtil = require("tweetnacl-util");
const asn1 = require('asn1.js');
const nacl = require('tweetnacl');
const util = require('tweetnacl-util');
// const Defs = require('./defs.js')
const reHex = /^\s*(?:[0-9A-Fa-f][0-9A-Fa-f]\s*)+$/


// Define the ASN.1 schema for Ed25519 private keys
const Ed25519PrivateKey = asn1.define('Ed25519PrivateKey', function () {
    return this.seq().obj(
        this.key('tbsCertificate').int(),
        this.key('signatureAlgorithm').seq().obj(
            this.key('algorithm').objid()
        ),
        this.key('key').octstr().obj(
            this.key('privateKey').octstr()
        ),
    );
});

// ASN.1 schema for Ed25519 public key
const Ed25519PublicKey = asn1.define('PublicKey', function () {
    this.seq().obj(
        this.key('tbsCertificate').seq().obj(
            this.key('signatureAlgorithm').objid(),
        ),
        this.key('signatureValue').bitstr()
    );
});

const readKeysFromPem = (publicKey, privateKey) => {
    // const pemToBuffer = (pem) => Buffer.from(pem
    //     .replace('-----BEGIN PUBLIC KEY-----', '')
    //     .replace('-----END PUBLIC KEY-----', '')
    //     .replace('-----BEGIN PRIVATE KEY-----', '')
    //     .replace('-----END PRIVATE KEY-----', '')
    //     .replace(/\n/g, ''), 'base64');
    //     const publicKeyBuffer = null;
    //     const privateKeyBuffer = null;
    // if(publicKey) {
    //     publicKeyBuffer = pemToBuffer(Buffer.from(publicKey));
    // }
    // if(privateKey) {
    //     privateKeyBuffer = pemToBuffer(Buffer.from(privateKey));
    // }

    return {
        publicKey: publicKey ? publicKey.split('\n')[1] : null,
        privateKey: privateKey ? privateKey.split('\n')[1] : null,
    };
};

const encryptWithSharedKey = (message, sharedKey) => {
    const nonce = nacl.randomBytes(nacl.box.nonceLength);
    const messageUint8 = util.decodeUTF8(message);
    const encrypted = nacl.box.after(messageUint8, nonce, sharedKey);
    const encryptedMessage = new Uint8Array(nonce.length + encrypted.length);
    encryptedMessage.set(nonce);
    encryptedMessage.set(encrypted, nonce.length);
    return util.encodeBase64(encryptedMessage);
}

const decryptWithShared = (encryptedMessage, sharedKey) => {
    const encryptedMessageUint8 = util.decodeBase64(encryptedMessage);
    const nonce = encryptedMessageUint8.slice(0, nacl.box.nonceLength);
    const message = encryptedMessageUint8.slice(nacl.box.nonceLength);
    const decrypted = nacl.box.open.after(message, nonce, sharedKey);
    if (!decrypted) {
        throw new Error('Failed to decrypt message.');
    }
    return util.encodeUTF8(decrypted);
}

const sign = (msg, privateKey) => {
    return libSodiumWrapper.crypto_sign_detached(msg, privateKey);
}

const signEncode = (payload, privateKey) => {
    const message = tweetnaclUtil.decodeUTF8(payload);
    const constsignedMsg = sign(message, privateKey)
    // console.log(constsignedMsg);
    return tweetnaclUtil.encodeBase64(constsignedMsg);
}

const verifySign = (signature, msg, publicKey) => {
    return libSodiumWrapper.crypto_sign_verify_detached(tweetnaclUtil.decodeBase64(signature), msg, keyToUint8Arrray(publicKey));
}

const generateKeyPair = () => {
    return nacl.box.keyPair()
}

const getSharedKey = (privateKey, publicKey) => {
    let parsedclientPublicKey = parsedPublicKey(readKeysFromPem(publicKey, null).publicKey)
    return nacl.box.before(parsedclientPublicKey.signatureValue.data, privateKey)
}

const parsedPrivateKey = (privateKey) => {
    return Ed25519PrivateKey.decode(Buffer.from(privateKey, 'base64'), 'der');
}


const parsedPublicKey = (publicKey) => {
    return Ed25519PublicKey.decode(Buffer.from(publicKey, 'base64'), 'der');
}
module.exports = {
    sign,
    signEncode,
    verifySign,
    generateKeyPair,
    getSharedKey,
    decryptWithShared,
    encryptWithSharedKey
};

function keyToUint8Arrray(key) {
    return Uint8Array.from(Buffer.from(decodeTextASN_1(key), 'base64'));
}
function decodeTextASN_1(val, privateKey = false) {
    try {
        let der = reHex.test(val) ? Hex.decode(val) : Base64.unarmor(val);
        let ans1 = ASN1.decode(der)
        if (ans1.sub) {
            let t = ans1.sub[ans1.sub.length - 1]
            if (privateKey) {
                return t.stream.b64Dump(t.posStart() + 4, t.posEnd())
            }
            return t.stream.b64Dump(t.posStart() + 3, t.posEnd())
        }
        throw new Error('Invalid key');
    } catch (e) {
        console.error(e);
        throw new Error('Invalid key');
    }
}