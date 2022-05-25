'use strict';

const winext = require('winext');
const Promise = winext.require('bluebird');
const lodash = winext.require('lodash');
const jwt = winext.require('jsonwebtoken');
const { convertSecretKey } = require('../utils/convert-util');
const loadConfiguration = require('../utils/load-configuration-util');
const { get, assign } = lodash;

function TokenGenerator(params = {}) {
  const loggerTracer = get(params, 'loggerTracer');

  const configure = loadConfiguration();

  const privateKey = get(configure, 'privateKey');
  const publicKey = get(configure, 'publicKey');

  const secretPrivate = convertSecretKey(privateKey, 'private');
  const secretPublic = convertSecretKey(publicKey, 'public');

  this.signToken = function ({ payload, options = {} }) {
    try {
      loggerTracer.debug(`func signToken has been start`, {
        args: {
          payload,
          options,
        },
      });
      const token = jwt.sign(payload, secretPrivate, options);
      loggerTracer.debug(`func signToken has been end`, {
        args: { token: token },
      });
      return token;
    } catch (err) {
      loggerTracer.error(`func signToken has error: ${err}`);
      return Promise.reject(err);
    }
  };

  this.refreshToken = function ({ token, options = {} }) {
    try {
      loggerTracer.debug(`func refreshToken has been start`, {
        args: {
          token,
          options,
        },
      });
      const payload = jwt.verify(token, secretPublic, options.verify);

      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti;

      const jwtSignOptions = assign({}, options, { jwtid: options.jwtid });
      const newToken = jwt.sign(payload, secretPrivate, jwtSignOptions);

      loggerTracer.debug(`func refreshToken has been end`, {
        args: {
          newToken: newToken,
        },
      });
      return newToken;
    } catch (err) {
      loggerTracer.error(`func refreshToken has error`, {
        args: err,
      });
      return Promise.reject(err);
    }
  };
}

exports = module.exports = new TokenGenerator();
exports.register = TokenGenerator;
