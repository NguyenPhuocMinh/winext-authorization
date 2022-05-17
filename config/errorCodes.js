'use strict';

const errorCodes = {
  NotFoundConfigKeyManagerJSON: {
    message: 'Not found configure keyManager.json',
    returnCode: 2000,
    statusCode: 500,
  },
  NotFoundPrivateKeyInKeyManagerJSON: {
    message: 'Not found private key in keyManager.json',
    returnCode: 2001,
    statusCode: 500,
  },
  TokenNotFound: {
    message: 'Token not found',
    returnCode: 2002,
    statusCode: 401,
  },
  TokenExpired: {
    message: 'Jwt expired',
    returnCode: 2003,
    statusCode: 401,
  },
  TokenInvalid: {
    message: 'Token invalid',
    returnCode: 2004,
    statusCode: 401,
  },
  TokenForbidden: {
    message: 'Method has been banned',
    returnCode: 2005,
    statusCode: 403,
  },
};

module.exports = errorCodes;
