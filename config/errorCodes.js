'use strict';

const errorCodes = {
  TokenNotFound: {
    message: 'Token not found',
    returnCode: 2001,
    statusCode: 401
  },
  TokenExpired: {
    message: 'Jwt expired',
    returnCode: 2002,
    statusCode: 401
  },
  TokenInvalid: {
    message: 'Token invalid',
    returnCode: 2003,
    statusCode: 401
  },
  TokenForbidden: {
    message: 'Method has been banned',
    returnCode: 2004,
    statusCode: 403
  }
};

module.exports = errorCodes;
