'use strict';

const winext = require('winext');
const lodash = winext.require('lodash');
const { get } = lodash;
const loadConfiguration = require('./load-configuration-util');
const { convertSecretKey } = require('./convert-util');

const loadSecret = () => {
  const configure = loadConfiguration();

  const privateKey = get(configure, 'privateKey');
  const publicKey = get(configure, 'publicKey');

  const secretPrivate = convertSecretKey(privateKey, 'private');
  const secretPublic = convertSecretKey(publicKey, 'public');

  return {
    secretPrivate,
    secretPublic,
  };
};

module.exports = loadSecret;
