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
      loggerTracer.data(`Function signToken has been start`, {
        args: {
          payload,
          signOptions,
        },
      });

      const opts = assign({}, options.defaultSignOptions, signOptions);
      const token = jwt.sign(payload, secretPrivate, opts);
      loggerTracer.data(`Function signToken has been end`, {
        args: { token: token },
      });
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
      loggerTracer.data(`Function refreshToken has been start`, {
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

      loggerTracer.data(`Function refreshToken has been end`, {
        args: {
          newToken: newToken,
        },
      });
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
