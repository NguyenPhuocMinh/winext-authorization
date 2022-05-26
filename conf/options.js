'use strict';

const winext = require('winext');
const uuidUtils = winext.uuidUtils;

const defaultSignOptions = {
  algorithm: 'HS256',
  keyid: uuidUtils.v4,
  expiresIn: '30m',
  notBefore: '2s',
};

const options = {
  defaultSignOptions,
};

module.exports = options;
