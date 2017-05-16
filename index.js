'use strict';

const Promise = require('bluebird');
const Restify = require('restify');
const Request = require('request-promise');
const RestifyValidation = require('node-restify-validation');
const Fs = Promise.promisifyAll(require('fs'));
const Crypto = require('crypto');
const WriteFile = Promise.promisify(require('fs').writeFile);
const Path = require('path');
const _ = require('lodash');
const Url = require('url');
const CloudFlareClient = require('cloudflare');
const Spawn = require('child_process').spawn;

const argv = require('minimist')(process.argv.slice(2));

const PORT = argv.port || process.env.SERVER_PORT || 7000;
const HOST = argv.host || process.env.SERVER_HOST || '127.0.0.1';
const GOGS_USERNAME = argv.gogsUsername || process.env.GOGS_USERNAME || 'admin';
const GOGS_PASSWORD = argv.gogsPassword || process.env.GOGS_PASSWORD || 'pass';
const GOGS_PORT = argv.gogsPort || process.env.GOGS_PORT || 3000;
const GOGS_TEMPLATE_USERNAME = argv.gogsTemplateUsername || process.env.GOGS_TEMPLATE_USERNAME || 'templates';
const GOGS_TEMPLATE_PASSWORD = argv.gogsTemplatePassword || process.env.GOGS_TEMPLATE_PASWORD || 'templatesquantri';
const GOGS_URL = argv.gogsUrl || process.env.GOGS_URL || 'http://127.0.0.1:3000';
const CLOUDFLARE_EMAIL = argv.cloudflareEmail || process.env.CLOUDFLARE_EMAIL || '';
const CLOUDFLARE_KEY = argv.cloudflareKey || process.env.CLOUDFLARE_KEY || '';
const PUBLIC_IP = argv.publicIp || process.env.PUBLIC_IP || '212.237.15.108';
const BASE_DOMAIN = argv.baseDomain || process.env.BASE_DOMAIN || 'easywebhub.me';
const REPOSITORY_DIR = argv.repositoryDir || process.env.REPOSITORY_DIR || '/app/ms-site-builder/repositories';
const NGINX_CONF_DIR = argv.nginxConfDir || process.env.NGINX_CONF_DIR || ' /etc/nginx';

const GOGS_API_PREFIX = '/api/v1';

const staticSalt = 'nhin thay la se biet'; // pointless

const AppInfo = require('./package.json');

function GenPassword(username) {
    let hasher = Crypto.createHash('sha256');

    hasher.update(username);
    hasher.update(staticSalt);
    return hasher.digest('hex');
}

function GenUsername(email) {
    return email.replace(/[@.]/g, '-');
}

const gogsRequest = Promise.coroutine(function*(options) {
    let username = options.username || server.gogs.username;
    let password = options.password || server.gogs.password;
    let headers = options.headers || {};

    let requestOptions = {
        method:                  options.method,
        uri:                     options.url,
        headers:                 headers,
        simple:                  false,
        json:                    true,
        resolveWithFullResponse: true,
        followAllRedirects:      true,
        auth:                    {
            user:            username,
            pass:            password,
            sendImmediately: true
        }
    };

    if (options.data)
        requestOptions.data = options.data;

    if (options.form)
        requestOptions.form = options.form;

    if (options.body)
        requestOptions.body = options.body;

    let res = yield Request(requestOptions);

    if (res.statusCode === 403)
        throw new Error('invalid gogs admin credential');

    return res;
});

const gogsGet = Promise.coroutine(function*(url, username, password) {
    return gogsRequest({
        method:   'GET',
        url:      url,
        username: username,
        password: password
    });
});

const gogsDel = Promise.coroutine(function*(url, username, password) {
    return gogsRequest({
        method:   'DELETE',
        url:      url,
        username: username,
        password: password
    });
});

const gogsPost = Promise.coroutine(function*(url, data, username, password) {
    return gogsRequest({
        method:   'POST',
        url:      url,
        body:     data,
        username: username,
        password: password,
        json:     true,
        headers:  {
            'Content-Type': 'application/json'
        }
    });
});

const gogsPostForm = Promise.coroutine(function*(url, data, username, password) {
    return gogsRequest({
        method:   'POST',
        url:      url,
        form:     data,
        username: username,
        password: password,
        json:     false
    });
});


const gogsPatch = Promise.coroutine(function*(url, data, username, password) {
    return gogsRequest({
        method:   'PATCH',
        url:      url,
        body:     data,
        username: username,
        password: password,
        json:     true,
        headers:  {
            'Content-Type': 'application/json'
        }
    });
});

const getUserInfo = Promise.coroutine(function*(username) {
    let url = server.gogs.url + GOGS_API_PREFIX + `/users/${username}`;
    let res = yield gogsGet(url);
    if (res.statusCode === 404)
        return null;

    return res.body;
});

const createUser = Promise.coroutine(function*(username, email) {
    let url = server.gogs.url + GOGS_API_PREFIX + `/admin/users`;
    // NOTE if username is 'user' gogs will fail
    let postData = {
        username:                  username,
        email:                     email,
        password:                  GenPassword(username),
        allow_create_organization: 'off'
    };
    let res = yield gogsPost(url, postData);
    return res.body;
});

const createUserIfNotExists = Promise.coroutine(function*(username, email) {
    let user = yield getUserInfo(username);
    email = email || `${username}@email.com`; // TODO NOTICE THIS
    // console.log('createUserIfNotExists user', user);
    if (user)
        return user;

    return yield createUser(username, email);
});

const extractGogsRepoInfo = function (gogsRepoInfo) {
    // console.log('gogsRepoInfo', gogsRepoInfo);
    return {
        id:       gogsRepoInfo['id'],
        name:     gogsRepoInfo['name'],
        fullName: gogsRepoInfo['full_name'],
        url:      gogsRepoInfo['clone_url'],
        private:  gogsRepoInfo['private']
    }
};

const extractGogsWebHookInfo = function (gogsWebHookInfo) {
    let ret = {
        id:          gogsWebHookInfo.id,
        url:         gogsWebHookInfo.config.url,
        contentType: gogsWebHookInfo.config.content_type,
        active:      gogsWebHookInfo.active
    };

    if (gogsWebHookInfo.config.secret) {
        ret.secret = gogsWebHookInfo.config.secret;
    }

    return ret;
};

function responseArraySuccess(res, data, headers) {
    headers = headers || {};
    res.json(200, {
        'data':         data,
        // "recordsFiltered": data.length,
        "recordsTotal": data.length
    }, headers);
}

function GetCsrfToken(html) {
    let matches = html.match(/_csrf" content="([^"]+)"/);
    if (matches.length !== 2) return null;
    return matches[1];
}

function GetUid(html) {
    let matches = html.match(/id="uid" name="uid" value="([^"]+)"/);
    if (matches.length !== 2) return null;
    return matches[1];
}

const server = Restify.createServer({
    name:    AppInfo.name,
    version: AppInfo.version
});

server.gogs = {
    url:              GOGS_URL,
    username:         GOGS_USERNAME,
    password:         GOGS_PASSWORD,
    templateUsername: GOGS_TEMPLATE_USERNAME,
    templatePassword: GOGS_TEMPLATE_PASSWORD
};

server.pre(Restify.pre.userAgentConnection());
server.pre(Restify.pre.sanitizePath());

server.use(Restify.CORS());
server.use(Restify.authorizationParser());
server.use(Restify.queryParser());
server.use(Restify.bodyParser());
server.use(RestifyValidation.validationPlugin({
    // Shows errors as an array
    errorsAsArray: false,
    // Not exclude incoming variables not specified in validator rules
    // forbidUndefinedVariables: false,
    errorHandler:  Restify.errors.InvalidArgumentError
}));


// Fs.readdirSync('api').forEach(name => {
//     if (!name.endsWith('.js')) return;
//     console.info(`load api ${name.substr(0, name.length - 3)}`);
//     require(`./api/${name}`)(server);
// });

const cfClient = new CloudFlareClient({
    email: CLOUDFLARE_EMAIL,
    key:   CLOUDFLARE_KEY,
});

server.post({
    url: '/migration', validation: {
        resources: {
            // email:          {isRequired: true, regex: /^[0-9a-zA-Z\-_@.]+$/},
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/}
            templateName:   {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        // create user if not exists
        // let username = GenUsername(req.params.email);
        let username = req.params.username;
        let user = yield createUserIfNotExists(username);
        let password = GenPassword(username);
        // get csrf token from GET http://localhost:3000/repo/migrate
        let migrationRepoUrl = server.gogs.url + `/repo/migrate`;

        let html = yield gogsGet(migrationRepoUrl, username, password);
        if (html.statusCode !== 200)
            return next(new Restify.InternalServerError('invalid user credential'));
        let csrfToken = GetCsrfToken(html.body);
        let uid = GetUid(html.body);

        // migration POST repo http://localhost:3000/repo/migrate
        let templateRepositoryUrl = `http://localhost:${GOGS_PORT}/${server.gogs.templateUsername}/${req.params.templateName}.git`;

        let response = yield gogsPostForm(migrationRepoUrl, {
            _csrf:         csrfToken,
            clone_addr:    templateRepositoryUrl,
            auth_username: server.gogs.templateUsername,
            auth_password: server.gogs.templatePassword,
            uid:           uid,
            repo_name:     req.params.repositoryName,
            private:       'on',
            description:   ''
        }, username, password);

        if (response.statusCode !== 200) {
            return next(new Restify.InternalServerError(response.body));
        }

        // migration failed too
        if (response.body.indexOf('master') === -1) {
            let matches = response.body.match(/ui negative message">[\r\n\s.]+<p>(.+)<\/p>/);
            if (matches.length === 2) {
                return next(new Restify.InternalServerError(matches[1]));
            } else {
                return next(new Restify.InternalServerError('migration failed, invalid src repository ?'));
            }
        } else {
            console.log('migration success');
            let repoInfo = yield getRepoInfo(username, req.params.repositoryName);
            res.json(repoInfo);
        }
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

const getRepoInfo = Promise.coroutine(function*(username, repoName) {
    // get all user's repo
    let createRepoUrl = server.gogs.url + GOGS_API_PREFIX + `/user/repos`;
    let password = GenPassword(username);

    let response = yield gogsGet(createRepoUrl, username, password);

    if (response.statusCode !== 200) {
        return null;
    }

    // find match repoName
    let infoList = _.map(response.body, info => {
        let repoInfo = extractGogsRepoInfo(info);
        repoInfo.username = username;
        repoInfo.password = password;
        return repoInfo;
    });

    let matchRepo = _.find(infoList, info => {
        return info.name === repoName;
    });

    return matchRepo;
});

server.post({
    url: '/repos', validation: {
        resources: {
            // email:          {isRequired: true, regex: /^[0-9a-zA-Z\-_@.]+$/},
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        // create user if not exists
        // let username = GenUsername(req.params.email);
        // let user = yield createUserIfNotExists(username, req.params.email);
        let username = req.params.username;
        let user = yield createUserIfNotExists(req.params.username);
        let password = GenPassword(req.params.username);

        // create repo
        let createRepoUrl = server.gogs.url + GOGS_API_PREFIX + `/admin/users/${username}/repos`;
        let response = yield gogsPost(createRepoUrl, {
            name:    req.params.repositoryName,
            private: true
        });
        // console.log('response', response);

        if (response.statusCode === 422)
            return next(new Restify.ConflictError(response.body.message ?
                response.body.message : JSON.stringify(response.body)));

        if (response.statusCode === 201) {
            let repoInfo = extractGogsRepoInfo(response.body);
            repoInfo.username = username;
            repoInfo.password = GenPassword(username);

            // add username and password to gogs repo's url
            let uri = Url.parse(repoInfo.url);
            uri.auth = `${repoInfo.username}:${repoInfo.password}`;
            repoInfo.url = Url.format(uri);

            res.json(repoInfo);
            return res.end();
        }
        return next(new Restify.ExpectationFailedError(response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// get list repos of an username
server.get({
    url: '/repos/:username', validation: {
        resources: {
            username: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let createRepoUrl = server.gogs.url + GOGS_API_PREFIX + `/user/repos`;
        let password = GenPassword(req.params.username);

        let response = yield gogsGet(createRepoUrl, req.params.username, password);

        if (response.statusCode === 200) {
            let ret = [];
            response.body.forEach(info => {
                let repoInfo = extractGogsRepoInfo(info);
                repoInfo.username = req.params.username;
                repoInfo.password = password;
                ret.push(repoInfo);
            });
            responseArraySuccess(res, ret);
            return res.end();
        }
        return next(new Restify.ExpectationFailedError(response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// get list web hook of an repo
server.get({
    url: '/repos/:username/:repositoryName/hooks', validation: {
        resources: {
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks`;
        let password = GenPassword(req.params.username);

        let response = yield gogsGet(repoWebHookUrl, req.params.username, password);

        // console.log('response.body', response.statusCode, response.body);
        if (response.statusCode === 200) {
            let ret = [];
            // console.log('response.body', response.body);
            response.body.forEach(webHook => {
                ret.push(extractGogsWebHookInfo(webHook));
            });
            return responseArraySuccess(res, ret);
        }

        return next(new Restify.ExpectationFailedError(response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// create web hook
server.post({
    url: '/repos/:username/:repositoryName/hooks', validation: {
        resources: {
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            url:            {isRequired: true, isUrl: true},
            secret:         {isRequired: false, regex: /^[0-9a-zA-Z \-_]+$/},

        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks`;
        let password = GenPassword(req.params.username);

        let postData = {
            type:   'gogs',
            config: {
                url:          req.params.url,
                secret:       req.params.secret,
                content_type: 'json'
            },
            events: ['push'],
            active: true
        };

        if (req.params.secret) {
            postData.config.secret = req.params.secret;
        }

        let response = yield gogsPost(repoWebHookUrl, postData);

        if (response.statusCode === 201) {
            res.json(extractGogsWebHookInfo(response.body));
            return res.end();
        }
        return next(new Restify.ExpectationFailedError(response.body === undefined ? 'no repository yet or invalid credential' : response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// edit web hook
server.patch({
    url: '/repos/:username/:repositoryName/hooks/:id', validation: {
        resources: {
            username: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            id:       {isRequired: true, isAlphanumeric: true},
            url:      {isRequired: false, isUrl: true},
            active:   {isRequired: false, isIn: ['false', 'true']},
            secret:   {isRequired: false, regex: /^[0-9a-zA-Z \-_]+$/}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks/${req.params.id}`;
        // let password = GenPassword(req.params.username);

        let postData = {
            config: {}
        };

        if (req.params.active !== undefined) postData.active = req.params.active;
        if (req.params.url) postData.config.url = req.params.url;
        if (req.params.secret) {
            postData.config.secret = req.params.secret;
            postData.secret = req.params.secret;
        }
        //console.log('postData', postData);
        let response = yield gogsPatch(repoWebHookUrl, postData);

        // console.log('response.body', response.statusCode, response.body);
        if (response.statusCode === 200) {
            res.json(extractGogsWebHookInfo(response.body));
            return res.end();
        }
        return next(new Restify.ExpectationFailedError(response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// remove web hook
server.del({
    url: '/repos/:username/:repositoryName/hooks/:id', validation: {
        resources: {
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            id:             {isRequired: true, isAlphanumeric: true}
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks/${req.params.id}`;
        let password = GenPassword(req.params.username);

        let response = yield gogsDel(repoWebHookUrl, req.params.username, password);

        // console.log('response.body', response.statusCode, response.body);
        if (response.statusCode === 204) {
            res.json(extractGogsWebHookInfo(response.body));
            return res.end();
        }
        return next(new Restify.ExpectationFailedError(response.body));
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

// create cloudflare sub domain
let cachedZoneId = '';
server.post({
    url: '/repos/create-cloudflare-subdomain', validation: {
        resources: {
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        let subDomain = `${req.params.repositoryName}.${req.params.username}`;
        // TODO create random domain name if repository name is invalid domain name

        // get cloudflare domains (zone)
        if (!cachedZoneId) {
            // chi co 1 domain easywebhub.me nen 1 cache la du
            let zones = yield cfClient.browseZones({name: BASE_DOMAIN});
            if (zones.count !== 1) {
                console.log('zones', zones);
                return next(new Restify.InternalServerError('base domain zone not found'));
            }
            cachedZoneId = zones.result[0].id;
        }

        // get dns list of domain
        let dnsEntries = yield cfClient.browseDNS(cachedZoneId, {name: subDomain + '.' + BASE_DOMAIN});
        let ret;
        if (dnsEntries.count === 1) {
            // edit
            let dnsEntry = dnsEntries.result[0];
            dnsEntry.content = PUBLIC_IP;
            dnsEntry.proxied = true;

            ret = yield cfClient.editDNS(dnsEntry);
        } else {
            // create new
            ret = yield cfClient.addDNS(CloudFlareClient.DNSRecord.create({
                "zone_id": cachedZoneId,
                "type":    'A',
                "name":    subDomain + '.' + BASE_DOMAIN,
                "content": PUBLIC_IP,
                "proxied": true
            }));
        }

        res.end('success');
    } catch (error) {
        try {
            let errMsg = error.response.body.errors[0].message;
            return next(new Restify.InternalServerError(errMsg));
        } catch (err) {
            return next(new Restify.InternalServerError(error.message));
        }
    }
}));

// create nginx virtual host
server.post({
    url: '/repos/create-nginx-virtual-host', validation: {
        resources: {
            username:       {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
            repositoryName: {isRequired: true, regex: /^[0-9a-zA-Z\-_]+$/},
        }
    }
}, Promise.coroutine(function*(req, res, next) {
    try {
        // find exists subdomain :repositoryName.:username.site
        // create new virtual host config
        // write config
        let subDomain = `${req.params.repositoryName}.${req.params.username}`;
        let domain = `${subDomain}.${BASE_DOMAIN}`;
        let root = Path.join(Path.resolve(`${REPOSITORY_DIR}/${req.params.username}/${req.params.repositoryName}`), 'build');
        let config = `server {
    listen 80;
    listen [::]:80;

    root ${root};
    index index.html index.htm;

    server_name ${domain};

    location / {
        try_files $uri $uri/ =404;
    }
}

`;
        yield WriteFile(Path.join(NGINX_CONF_DIR, 'sites-enabled', domain + '.conf'), config);
        yield WriteFile(Path.join(NGINX_CONF_DIR, 'sites-available', domain + '.conf'), config);
        // trigger nginx reload
        Spawn('nginx', ['-s', 'reload']);
        res.end('success');
    } catch (error) {
        return next(new Restify.InternalServerError(error.message));
    }
}));

server.listen(PORT, HOST, () => {
    console.log('%s listening at %s', server.name, server.url);
});
