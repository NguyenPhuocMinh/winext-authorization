'use strict';

const winext = require('winext');
const Promise = winext.require('bluebird');
const lodash = winext.require('lodash');
const chalk = winext.require('chalk');
const jwt = winext.require('jsonwebtoken');
const { convertSecretKey } = require('./convert');
const loadConfiguration = require('./load-configuration');
const { name, version } = require('../package.json');
const { get, assign } = lodash;

function TokenGenerator(params = {}) {
  const requestId = get(params, 'requestId');
  const loggerFactory = get(params, 'loggerFactory');
  const loggerTracer = get(params, 'loggerTracer');

  const configure = loadConfiguration();

  const privateKey = get(configure, 'privateKey');
  const publicKey = get(configure, 'publicKey');

  const secretPrivate = convertSecretKey(privateKey, 'private');
  const secretPublic = convertSecretKey(publicKey, 'public');

  this.signToken = function ({ payload, options = {} }) {
    try {
      loggerTracer.debug(chalk.blue.bold(`Load function signToken by ${name}-${version} successfully!`));
      loggerFactory.debug(`func signToken has been start`, {
        requestId: `${requestId}`,
        args: {
          payload,
          options,
        },
      });
      const token = jwt.sign(payload, secretPrivate, options);
      loggerFactory.debug(`func signToken has been end`, {
        requestId: `${requestId}`,
        args: { token: token },
      });
      return token;
    } catch (err) {
      loggerFactory.error(`func signToken has error: ${err}`, {
        requestId: `${requestId}`,
      });
      return Promise.reject(err);
    }
  };

  this.refreshToken = function ({ token, options = {} }) {
    try {
      loggerTracer.debug(chalk.blue.bold(`Load function refreshToken by ${name}-${version} successfully!`));
      loggerFactory.debug(`func refreshToken has been start`, {
        requestId: `${requestId}`,
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

      loggerFactory.debug(`func refreshToken has been end`, {
        requestId: `${requestId}`,
        args: {
          newToken: newToken,
        },
      });
      return newToken;
    } catch (err) {
      loggerFactory.error(`func refreshToken has error: ${err}`, {
        requestId: `${requestId}`,
      });
      return Promise.reject(err);
    }
  };
}

exports = module.exports = new TokenGenerator();
exports.register = TokenGenerator;
