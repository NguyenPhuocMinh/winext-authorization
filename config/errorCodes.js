'use strict';

const errorCodes = {
  TokenExpired: {
    message: 'Jwt expired',
    returnCode: 2001,
    statusCode: 401
  },
  TokenInvalid: {
    message: 'Token invalid',
    returnCode: 2002,
    statusCode: 401
  },
  TokenForbidden: {
    message: 'Method has been banned',
    returnCode: 2003,
    statusCode: 403
  }
};

module.exports = errorCodes;
