'use strict';

const winext = require('winext');
const Promise = winext.require('bluebird');
const lodash = winext.require('lodash');
const chalk = winext.require('chalk');
const jwt = require('jsonwebtoken');
const errorCodes = require('../config/errorCodes');
const { get, isEmpty, find, includes } = lodash;
const { name, version } = require('../package.json');

function Authorization(params = {}) {
  const config = get(params, 'config');
  const requestId = get(params, 'requestId');
  const loggerFactory = get(params, 'loggerFactory');
  const loggerTracer = get(params, 'loggerTracer');
  const errorManager = get(params, 'errorManager');

  const enable = get(config, 'enable', false);
  const secretKey = get(config, 'secretKey');
  const enablePaths = get(config, 'enablePaths');
  const publicPaths = get(config, 'publicPaths');
  const protectedPaths = get(config, 'protectedPaths');

  this.noVerifyToken = async function (request, response, next) {
    try {
      loggerFactory.data(`Method no need check token start`, {
        requestId: `${requestId}`,
        args: {
          enable,
          secretKey,
          method: request.method,
          path: request.path,
        },
      });
      loggerTracer.debug(chalk.blue.bold(`Load function noVerifyToken by ${name}-${version} successfully!`));

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
      loggerFactory.error(`Method no need check token has error : ${err}`, {
        requestId: `${requestId}`,
        args: { err },
      });
      return Promise.reject(err);
    }
  };

  this.verifyTokenMiddleware = async function (request, response, next) {
    try {
      loggerFactory.data(`Check token has been start with args`, {
        requestId: `${requestId}`,
        args: {
          enable,
          secretKey,
          hasToken: request.hasToken,
          tokenFound: request.header('x-access-token'),
        },
      });

      loggerTracer.debug(chalk.blue.bold(`Load function verifyTokenMiddleware by ${name}-${version} successfully!`));

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
         * get token from request headers
         */
        const token = request.header('x-access-token');
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
          await jwt.verify(token, secretKey, (err, decoded) => {
            if (err) {
              loggerFactory.error(`Verify token has error`, {
                requestId: `${requestId}`,
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
                loggerFactory.data(`Verify token decoded`, {
                  requestId: `${requestId}`,
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
      loggerFactory.error(`Check token has been error ${err}`, {
        requestId: `${requestId}`,
        args: { err },
      });
      return Promise.reject(err);
    }
  };

  this.publicRouters = async function (request, response, next) {
    try {
      loggerFactory.data(`Check public path has args`, {
        requestId: `${requestId}`,
        args: {
          enable,
          secretKey,
          hasToken: request.hasToken ? request.hasToken : false,
          accessToken: request.accessToken ? request.accessToken : null,
          tokenFound: request.header('x-access-token'),
        },
      });

      loggerTracer.debug(chalk.blue.bold(`Load function publicRouters by ${name}-${version} successfully!`));

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
          request.isPublic = true;
          return next();
        } else {
          request.isPublic = false;
          return next();
        }
      }
    } catch (err) {
      loggerFactory.error(`Check public path has been error ${err}`, {
        requestId: `${requestId}`,
        args: { err },
      });

      return Promise.reject(err);
    }
  };

  this.protectedRouters = async function (request, response, next) {
    try {
      loggerFactory.data(`Check protected path has args`, {
        requestId: `${requestId}`,
        args: {
          enable,
          hasToken: request.hasToken ? request.hasToken : false,
          accessToken: request.accessToken ? request.accessToken : null,
          publicPath: request.isPublic ? request.isPublic : false,
          tokenFound: request.header('x-access-token'),
        },
      });

      loggerTracer.debug(chalk.blue.bold(`Load function protectedRouters by ${name}-${version} successfully!`));

      const { route, method, path } = request;

      if (!enable || request.hasToken || request.isPublic) {
        return next();
      } else {
        loggerFactory.data(`Check protected path args`, {
          requestId: `${requestId}`,
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
            loggerFactory.data(`protectedPermission not includes userPermissions`, {
              requestId: `${requestId}`,
            });
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
          loggerFactory.data(`accessToken or protectedPath isEmpty`, {
            requestId: `${requestId}`,
          });
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

      loggerFactory.data(`Check protected path has been end`, {
        requestId: `${requestId}`,
      });
    } catch (err) {
      loggerFactory.error(`Check protected path has error : ${err}`, {
        requestId: `${requestId}`,
        args: { err },
      });
      return Promise.reject(err);
    }
  };

  this.jwt = jwt;
}

exports = module.exports = new Authorization();
exports.register = Authorization;
