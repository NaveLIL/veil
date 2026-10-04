// Local USB-only design server. Never starts the authenticated App.tsx entry.
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
const mobile = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
process.chdir(mobile);
process.env.EXPO_OFFLINE = '1';
const require = createRequire(path.join(mobile, 'package.json'));
const expoRequire = createRequire(require.resolve('expo/package.json'));
const { getDefaultConfig } = expoRequire('@expo/metro-config');
const Metro = expoRequire('metro');
const { loadConfig } = expoRequire('metro-config');
const config = await loadConfig({ cwd: mobile }, getDefaultConfig(mobile));
config.server.port = 8081;
config.maxWorkers = 2;
const enhance = config.server.enhanceMiddleware;
config.server.enhanceMiddleware = (middleware, server) => {
  const delegate = enhance ? enhance(middleware, server) : middleware;
  return (request, response, next) => {
    if (request.url?.split('?')[0] === '/status') {
      response.setHeader('Content-Type', 'text/plain');
      response.end('packager-status:running');
    } else delegate(request, response, next);
  };
};
const server = await Metro.runServer(config, { host: '127.0.0.1', port: 8081 });
if (server.address().address !== '127.0.0.1') { server.close(); throw Error('Design server must listen on loopback only'); }
console.log('Veil Design Live: USB / 127.0.0.1:8081 / design-preview-index');
