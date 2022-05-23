'use strict';

const path = require('path');
const fs = require('fs');
const winext = require('winext');
const errorManager = winext.require('winext-error-manager');
const errorCodes = require('../config/errorCodes');

const loadConfiguration = () => {
  const configurePath = path.join(process.cwd(), 'keyManager.json');
  if (!configurePath) {
    throw errorManager.newError('NotFoundConfigKeyManagerJSON', errorCodes);
  }

  const json = fs.readFileSync(configurePath);
  const configure = JSON.parse(json.toString());

  return configure;
};

module.exports = loadConfiguration;
