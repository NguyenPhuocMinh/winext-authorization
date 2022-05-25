'use strict';

const winext = require('winext');
const uuidUtils = winext.uuidUtils;

const defaultOptions = {
  algorithm: 'HS256',
  keyid: uuidUtils.v4,
  expiresIn: '30m',
  notBefore: '2s',
};

const options = {
  defaultOptions,
};

module.exports = options;
