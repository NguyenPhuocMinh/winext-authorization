'use strict';

const winext = require('winext');
const Promise = winext.require('bluebird');
const lodash = winext.require('lodash');
const jwt = winext.require('jsonwebtoken');
const loadSecret = require('../utils/load-secret-util');
const options = require('../conf/options');
const { get, assign } = lodash;

function TokenGenerator(params = {}) {
  const loggerTracer = get(params, 'loggerTracer');

  const { secretPrivate, secretPublic } = loadSecret();

  /**
   * Sign token
   * @example
   * const token = tokenGenerator.signToken({
   *    payload: { username: 'John Doe' },
   *    signOptions: { audience: 'myaud', issuer: 'myissuer', jwtid: '1', subject: 'user' }
   * })
   * @returns
   */
  this.signToken = function ({ payload, signOptions = {} }) {
    try {
      loggerTracer.info(`Function signToken has been start`, {
        args: {
          payload,
          signOptions,
        },
      });

      const opts = assign({}, options.defaultSignOptions, signOptions);
      const token = jwt.sign(payload, secretPrivate, opts);

      const decodedToken = jwt.decode(token, { complete: true });
      loggerTracer.verbose(`Decoded sign token info`, {
        args: decodedToken,
      });

      loggerTracer.info(`Function signToken has been end`);

      return token;
    } catch (err) {
      loggerTracer.error(`Function signToken has error`, {
        args: err.message,
      });
      return Promise.reject(err);
    }
  };

  /**
   * Refresh token
   * @example
   * const refreshToken = tokenGenerator.refreshToken({
   *    token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
   *    refreshOptions: { verify: { audience: 'myaud', issuer: 'myissuer' }, jwtid: '2' }
   * })
   * @returns
   */
  this.refreshToken = function ({ token, refreshOptions = {} }) {
    try {
      loggerTracer.info(`Function refreshToken has been start`, {
        args: {
          token,
          refreshOptions,
        },
      });
      const payload = jwt.verify(token, secretPublic, refreshOptions.verify);

      delete payload.iat;
      delete payload.exp;
      delete payload.nbf;
      delete payload.jti;

      const opts = assign({}, options.defaultSignOptions, refreshOptions, { jwtid: refreshOptions.jwtid });
      const newToken = jwt.sign(payload, secretPrivate, opts);

      const decodedToken = jwt.decode(newToken, { complete: true });
      loggerTracer.verbose(`Decoded refresh token info`, {
        args: decodedToken,
      });

      loggerTracer.info(`Function refreshToken has been end`);
      return { newToken, payload };
    } catch (err) {
      loggerTracer.error(`Function refreshToken has error`, {
        args: err.message,
      });
      return Promise.reject(err);
    }
  };
}

exports = module.exports = new TokenGenerator();
exports.register = TokenGenerator;
