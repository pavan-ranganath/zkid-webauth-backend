var libSodiumWrapper = require("libsodium-wrappers");
var tweetnaclUtil = require("tweetnacl-util");

const encrypt = (msg, publicKey) => {
    const msgDecodeutf8 = tweetnaclUtil.decodeUTF8(msg);
    let curve25519publicKey = libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(hexToUint8Arrray(publicKey));
    const encryptedMessage = libSodiumWrapper.crypto_box_seal(msgDecodeutf8, curve25519publicKey);
    return tweetnaclUtil.encodeBase64(encryptedMessage);
}

const decrypt = (ciphertext, publicKey, privateKey) => {
    const decodedCiphertext = tweetnaclUtil.decodeBase64(ciphertext);

    const curvePublicKey = libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(hexToUint8Arrray(publicKey));
    const curvePrivateKey = libSodiumWrapper.crypto_sign_ed25519_sk_to_curve25519(hexToUint8Arrray(privateKey));

    const decrypted = libSodiumWrapper.crypto_box_seal_open(decodedCiphertext, curvePublicKey, curvePrivateKey);

    if (!decrypted) {
        return null;
    }
    return tweetnaclUtil.encodeUTF8(decrypted);
}

const decryptWithShared = (ciphertext, sharedKey,nonce) => {
    const decodedCiphertext = tweetnaclUtil.decodeBase64(ciphertext);
    const decrypted = libSodiumWrapper.crypto_box_open_easy_afternm(decodedCiphertext, hexToUint8Arrray(nonce),  hexToUint8Arrray(sharedKey));

    if (!decrypted) {
        return null;
    }
    return tweetnaclUtil.encodeUTF8(decrypted);
}

const sign = (msg, privateKey)=> {
    return libSodiumWrapper.crypto_sign_detached(msg, privateKey);
}

const signEncode = (payload, privateKey) => {
    const message = tweetnaclUtil.decodeUTF8(payload);
    const constsignedMsg = sign(message, privateKey)
    // console.log(constsignedMsg);
    return tweetnaclUtil.encodeBase64(constsignedMsg);
}

const verifySign = (signature, msg, publicKey) => {
    return libSodiumWrapper.crypto_sign_verify_detached(tweetnaclUtil.decodeBase64(signature),msg,hexToUint8Arrray(publicKey));
}

const  generateKeyPair = async(format="base64") =>  {
    return libSodiumWrapper.crypto_sign_keypair(format)
}

const getSharedKey = (privateKey, publicKey) => {
    return  libSodiumWrapper.crypto_scalarmult(
        libSodiumWrapper.crypto_sign_ed25519_sk_to_curve25519(hexToUint8Arrray(privateKey)), 
        libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(hexToUint8Arrray(publicKey)),
        "base64"
        )
}

const encryptWithSharedKey = (msg, sharedKey, nonce) =>{
    const encryptedMessage = libSodiumWrapper.crypto_box_easy_afternm(msg,hexToUint8Arrray(nonce), hexToUint8Arrray(sharedKey));
    return tweetnaclUtil.encodeBase64(encryptedMessage);
}
module.exports = {
  encrypt,
  decrypt,
  sign,
  signEncode,
  verifySign,
  generateKeyPair,
  getSharedKey,
  decryptWithShared,
  encryptWithSharedKey
};

function hexToUint8Arrray(key) {
    // return tweetnaclUtil.decodeBase64(key);
    return Uint8Array.from(Buffer.from(key, 'base64'));
}
