'use strict';

const winext = require('winext');
const Promise = winext.require('bluebird');
const lodash = winext.require('lodash');
const chalk = winext.require('chalk');
const jwt = winext.require('jsonwebtoken');
const errorCodes = require('../config/errorCodes');
const tokenGenerator = require('../tokens/token-generator');
const { get, isEmpty, find, includes } = lodash;

function Authorization(params = {}) {
  const config = get(params, 'config');
  const loggerTracer = get(params, 'loggerTracer');
  const errorManager = get(params, 'errorManager');

  const enable = get(config, 'enable', false);
  const secretKey = get(config, 'secretKey');
  const enablePaths = get(config, 'enablePaths');
  const publicPaths = get(config, 'publicPaths');
  const protectedPaths = get(config, 'protectedPaths');

  const ATTRIBUTE_TOKEN_KEY = 'x-access-token';

  this.noVerifyToken = async function (request, response, next) {
    try {
      loggerTracer.debug(`Method no need check token start`, {
        args: {
          enable,
          secretKey,
          method: request.method,
          path: request.path,
        },
      });

      const { route, method } = request;

      if (!enable) {
        return next();
      } else {
        const findEnablePath = find(enablePaths, (item) => item.pathName === route.path && item.method === method);
        if (!isEmpty(findEnablePath)) {
          request.hasToken = true;
          return next();
        } else {
          request.hasToken = false;
          return next();
        }
      }
    } catch (err) {
      loggerTracer.error(`Method no need check token has error : ${err}`, {
        args: { err },
      });
      return Promise.reject(err);
    }
  };

  this.verifyTokenMiddleware = async function (request, response, next) {
    try {
      loggerTracer.debug(`Check token has been start with args`, {
        args: {
          enable,
          secretKey,
          hasToken: request.hasToken,
          tokenFound: request.header(ATTRIBUTE_TOKEN_KEY) || request.cookies[ATTRIBUTE_TOKEN_KEY],
        },
      });

      const { route, method, path } = request;

      const findPathPublic = find(publicPaths, (item) => item.pathName === route.path && item.method === method);
      const enablePublicPath = get(findPathPublic, 'enable', false);

      const findProtectedPath = find(protectedPaths, (item) => item.pathName === route.path && item.method === method);
      const enableProtectedPath = get(findProtectedPath, 'enable');

      if (!enable || request.hasToken) {
        return next();
      } else if (!isEmpty(findPathPublic) && !enablePublicPath) {
        return next();
      } else if (!isEmpty(findProtectedPath) && !enableProtectedPath) {
        return next();
      } else {
        /**
         * get token from request headers or request cookie
         */
        const token = request.header(ATTRIBUTE_TOKEN_KEY) || request.cookies[ATTRIBUTE_TOKEN_KEY];
        if (isEmpty(token)) {
          const tokenNotFoundError = errorManager.newError('TokenNotFound', errorCodes);

          return response.status(tokenNotFoundError.statusCode).send({
            data: {},
            method: method,
            endpoint: path,
            name: tokenNotFoundError.name,
            message: tokenNotFoundError.message,
            returnCode: tokenNotFoundError.returnCode,
            statusCode: tokenNotFoundError.statusCode,
          });
        } else {
          /**
           * verify token
           */
          jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
              loggerTracer.error(`Verify token has error`, {
                args: { name: err.name, message: err.message },
              });

              const tokenExpiredError = errorManager.newError('TokenExpired', errorCodes);

              response.status(tokenExpiredError.statusCode).send({
                data: {},
                method: method,
                endpoint: path,
                name: tokenExpiredError.name,
                message: tokenExpiredError.message,
                returnCode: tokenExpiredError.returnCode,
                statusCode: tokenExpiredError.statusCode,
              });
            } else {
              if (!isEmpty(decoded)) {
                loggerTracer.debug(`Verify token decoded`, {
                  args: { decoded },
                });

                request.accessToken = {
                  permissions: get(decoded, 'userLogin.permissions'),
                  iat: decoded.iat,
                  exp: decoded.exp,
                };
                return next();
              }
            }
          });
        }
      }
    } catch (err) {
      loggerTracer.error(`Check token has been error`, {
        args: err,
      });
      return Promise.reject(err);
    }
  };

  this.publicRouters = async function (request, response, next) {
    try {
      loggerTracer.debug(`Check public path has args`, {
        args: {
          enable,
          secretKey,
          hasToken: request.hasToken ? request.hasToken : false,
          accessToken: request.accessToken ? request.accessToken : null,
          tokenFound: request.header(ATTRIBUTE_TOKEN_KEY) || request.cookies[ATTRIBUTE_TOKEN_KEY],
        },
      });

      const { route, method } = request;

      if (!enable || request.hasToken) {
        return next();
      } else {
        const findPathPublic = find(publicPaths, (item) => item.pathName === route.path && item.method === method);
        if (!isEmpty(findPathPublic)) {
          const enablePublicPath = get(findPathPublic, 'enable');
          if (!enablePublicPath) {
            request.isPublic = true;
          } else {
            request.isPublic = false;
          }
          return next();
        } else {
          request.isPublic = false;
          return next();
        }
      }
    } catch (err) {
      loggerTracer.error(`Check public path has been error`, {
        args: err,
      });

      return Promise.reject(err);
    }
  };

  this.protectedRouters = async function (request, response, next) {
    try {
      loggerTracer.debug(`Check protected path has args`, {
        args: {
          enable,
          hasToken: request.hasToken ? request.hasToken : false,
          accessToken: request.accessToken ? request.accessToken : null,
          publicPath: request.isPublic ? request.isPublic : false,
          tokenFound: request.header(ATTRIBUTE_TOKEN_KEY) || request.cookies[ATTRIBUTE_TOKEN_KEY],
        },
      });

      const { route, method, path } = request;

      if (!enable || request.hasToken || request.isPublic) {
        return next();
      } else {
        loggerTracer.debug(`Check protected path args`, {
          args: {
            enable,
            accessToken: request.accessToken ? request.accessToken : null,
          },
        });
        const findProtectedPath = find(
          protectedPaths,
          (item) => item.pathName === route.path && item.method === method
        );

        if (!isEmpty(request.accessToken) && !isEmpty(findProtectedPath)) {
          const userPermissions = get(request, 'accessToken.permissions');
          loggerTracer.info(chalk.blue.bold(`User permissions : ${userPermissions}`));
          const protectedPermission = get(findProtectedPath, 'permission');
          const enableProtectedPath = get(findProtectedPath, 'enable');
          if (includes(userPermissions, protectedPermission) || !enableProtectedPath) {
            return next();
          } else {
            loggerTracer.debug(`protectedPermission not includes userPermissions`);
            const tokenForbiddenError = errorManager.newError('TokenForbidden', errorCodes);
            response.status(tokenForbiddenError.statusCode).send({
              data: {},
              method: method,
              endpoint: path,
              name: tokenForbiddenError.name,
              message: tokenForbiddenError.message,
              returnCode: tokenForbiddenError.returnCode,
              statusCode: tokenForbiddenError.statusCode,
            });
          }
        } else {
          loggerTracer.debug(`accessToken or protectedPath isEmpty`);
          const tokenForbiddenError = errorManager.newError('TokenForbidden', errorCodes);
          response.status(tokenForbiddenError.statusCode).send({
            data: {},
            method: method,
            endpoint: path,
            name: tokenForbiddenError.name,
            message: tokenForbiddenError.message,
            returnCode: tokenForbiddenError.returnCode,
            statusCode: tokenForbiddenError.statusCode,
          });
        }
      }

      loggerTracer.debug(`Check protected path has been end`);
    } catch (err) {
      loggerTracer.error(`Check protected path has error`, {
        args: err,
      });
      return Promise.reject(err);
    }
  };

  this.tokenGenerator = tokenGenerator;
}

exports = module.exports = new Authorization();
exports.register = Authorization;
