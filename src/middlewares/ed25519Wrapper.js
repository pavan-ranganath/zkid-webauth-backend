var libSodiumWrapper = require("libsodium-wrappers");
var tweetnaclUtil = require("tweetnacl-util");

const encrypt = (msg, publicKey) => {
    const msgDecodeutf8 = tweetnaclUtil.decodeUTF8(msg);
    let curve25519publicKey = libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(publicKey);
    const encryptedMessage = libSodiumWrapper.crypto_box_seal(msgDecodeutf8, curve25519publicKey);
    return tweetnaclUtil.encodeBase64(encryptedMessage);
}

const decrypt = (ciphertext, publicKey, privateKey) => {
    const decodedCiphertext = tweetnaclUtil.decodeBase64(ciphertext);

    const curvePublicKey = libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(publicKey);
    const curvePrivateKey = libSodiumWrapper.crypto_sign_ed25519_sk_to_curve25519(privateKey);

    const decrypted = libSodiumWrapper.crypto_box_seal_open(decodedCiphertext, curvePublicKey, curvePrivateKey);

    if (!decrypted) {
        return null;
    }
    return tweetnaclUtil.encodeUTF8(decrypted);
}

const decryptWithShared = (ciphertext, sharedKey,nonce) => {
    const decodedCiphertext = tweetnaclUtil.decodeBase64(ciphertext);
    const decrypted = libSodiumWrapper.crypto_box_open_easy_afternm(decodedCiphertext, nonce, sharedKey);

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
    return libSodiumWrapper.crypto_sign_verify_detached(tweetnaclUtil.decodeBase64(signature),msg,publicKey);
}

const  generateKeyPair = async() =>  {
    return libSodiumWrapper.crypto_sign_keypair()
}

const getSharedKey = (privateKey, publicKey) => {
    return  libSodiumWrapper.crypto_scalarmult(libSodiumWrapper.crypto_sign_ed25519_sk_to_curve25519(privateKey), libSodiumWrapper.crypto_sign_ed25519_pk_to_curve25519(publicKey))
}

const encryptWithSharedKey = (msg, sharedKey, nonce) =>{
    const encryptedMessage = libSodiumWrapper.crypto_box_easy_afternm(msg,nonce, sharedKey);
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