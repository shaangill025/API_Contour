'use strict';
module.exports = {
  flowFile: '/fixture/flows.json', userDir: '/data', credentialSecret: false,
  httpAdminRoot: false, uiHost: '127.0.0.1', uiPort: Number(process.env.FIXTURE_PORT),
  httpRequestTimeout: 5000, apiMaxLength: '1kb',
  logging: {console: {level: 'off', metrics: false, audit: false}},
  externalModules: {autoInstall: false, palette: {allowInstall: false}},
};
