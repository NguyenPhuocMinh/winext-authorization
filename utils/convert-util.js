'use strict';

const convertSecretKey = (secretKey, mode) => {
  let secret = secretKey;
  if (mode === 'private') {
    secret = '-----BEGIN RSA PRIVATE KEY-----\n';
    for (let i = 0; i < secretKey.length; i = i + 64) {
      secret += secretKey.substring(i, i + 64);
      secret += '\n';
    }
    secret += '-----END RSA PRIVATE KEY-----';
    return secret;
  } else if (mode === 'public') {
    secret = '-----BEGIN PUBLIC KEY-----\n';
    for (let i = 0; i < secretKey.length; i = i + 64) {
      secret += secretKey.substring(i, i + 64);
      secret += '\n';
    }
    secret += '-----END PUBLIC KEY-----';
  } else {
    return secret;
  }
};

module.exports = {
  convertSecretKey,
};
