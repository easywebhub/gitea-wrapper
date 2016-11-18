'use strict';

const Promise = require('bluebird');
const Restify = require('restify');
const Request = require('request-promise');
const RestifyValidation = require('node-restify-validation');
const Fs = Promise.promisifyAll(require('fs'));

const argv = require('minimist')(process.argv.slice(2));
console.dir(argv);
const PORT = argv.port || process.env.SERVER_PORT || 7000;
const HOST = argv.host || process.env.SERVER_HOST || '127.0.0.1';
const GOGS_USERNAME = argv.gogsUsername || process.env.GOGS_USERNAME || 'root';
const GOGS_PASSWORD = argv.gogsPassword || process.env.GOGS_PASSWORD || 'pass';
const GOGS_URL = argv.gogsUrl || process.env.GOGS_URL || 'http://127.0.0.1:3000';

const AppInfo = require('./package.json');

const server = Restify.createServer({
    name:    AppInfo.name,
    version: AppInfo.version
});

server.gogs = {
    url:      GOGS_URL,
    username: GOGS_USERNAME,
    password: GOGS_PASSWORD
};

console.log('server.gogs', server.gogs);

server.pre(Restify.pre.userAgentConnection());
server.pre(Restify.pre.sanitizePath());

server.use(Restify.CORS());
server.use(Restify.authorizationParser());
server.use(Restify.queryParser());
server.use(Restify.bodyParser());
server.use(RestifyValidation.validationPlugin({
    // Shows errors as an array
    errorsAsArray:            false,
    // Not exclude incoming variables not specified in validator rules
    forbidUndefinedVariables: false,
    errorHandler:             Restify.errors.InvalidArgumentError
}));


Fs.readdirSync('api').forEach(name => {
    if (!name.endsWith('.js')) return;
    console.info(`load api ${name.substr(0, name.length - 3)}`);
    require(`./api/${name}`)(server);
});

server.listen(PORT, HOST, () => {
    console.log('%s listening at %s', server.name, server.url);
});
