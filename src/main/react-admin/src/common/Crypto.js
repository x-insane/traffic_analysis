import CryptoJS from 'crypto-js';

let key = CryptoJS.enc.Hex.parse(window.key);
let iv = CryptoJS.enc.Hex.parse(window.key.substring(0, 32));

function resetKey(new_key) {
    window.key = new_key;
    key = CryptoJS.enc.Hex.parse(window.key);
    iv = CryptoJS.enc.Hex.parse(window.key.substring(0, 32));
    if (window.sessionStorage)
        window.sessionStorage.setItem("key", window.key);
}

//加密方法
function encrypt(word) {
    if (!window.key)
        return word;
    let encrypted = CryptoJS.AES.encrypt(word, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return encrypted.toString();
}

window.encrypt = encrypt;

//解密方法
function decrypt(word) {
    if (!window.key)
        return word;
    let decrypted = CryptoJS.AES.decrypt(word, key, {
        iv: iv,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return decrypted.toString(CryptoJS.enc.Utf8);
}

window.decrypt = decrypt;

// MD5
const md5 = text => CryptoJS.MD5(text).toString();

export {
    encrypt,
    decrypt,
    md5,
    resetKey
};