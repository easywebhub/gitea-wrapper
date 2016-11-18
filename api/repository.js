'use strict';

const Restify = require('restify');
const Crypto = require('crypto');
const Promise = require('bluebird');
const Request = require('request-promise');

const GOGS_API_PREFIX = '/api/v1';

const STATIC_SALT = 'nhin thay la se biet'; // pointless
let server;

function GenPassword(username) {
    let hasher = Crypto.createHash('sha256');

    hasher.update(username);
    hasher.update(STATIC_SALT);
    return hasher.digest('hex');
}

const gogsRequest = Promise.coroutine(function*(options) {
    let username = options.username || server.gogs.username;
    let password = options.password || server.gogs.password;

    let requestOptions = {
        method:                  options.method,
        uri:                     options.url,
        simple:                  false,
        json:                    true,
        resolveWithFullResponse: true,
        auth:                    {
            user:            username,
            pass:            password,
            sendImmediately: true
        }
    };

    if (options.data)
        requestOptions.data = options.data;

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
        data:     data,
        username: username,
        password: password
    });
});

const getUserInfo = Promise.coroutine(function*(username) {
    let url = server.gogs.url + GOGS_API_PREFIX + `/users/${username}`;
    let res = yield gogsGet(url);
    if (res.statusCode === 404)
        return null;

    return res.body;
});

const createUser = Promise.coroutine(function*(username) {
    let url = server.gogs.url + GOGS_API_PREFIX + `/admin/users`;
    let postData = {
        username: username,
        email:    `${username}@email.com`,
        password: GenPassword(username)
    };
    let res = yield gogsPost(url, postData);
    return res.body;
});

const createUserIfNotExists = Promise.coroutine(function*(username) {
    let user = yield getUserInfo(username);
    if (user)
        return user;

    return yield createUser(username);
});

const extractGogsRepoInfo = function (gogsRepoInfo) {
    console.log('gogsRepoInfo', gogsRepoInfo);
    return {
        id:       gogsRepoInfo['id'],
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

module.exports = sv => {
    server = sv;
    /**
     * Create new repository
     * {
     *      username: '',
     *      repositoryName: ''
     * }
     * Response
     * {
     *  "html_url": "http://localhost:3000/aa/repos-1",
     *  "full_name": "",
     * }
     */
    server.post({
        url: '/repos', validation: {
            resources: {
                username:       {isRequired: true, isAlphanumeric: true},
                repositoryName: {isRequired: true, notRegex: /[0-9a-zA-Z\-_]+/g}
            }
        }
    }, Promise.coroutine(function*(req, res, next) {
        try {
            // create user if not exists
            let user = yield createUserIfNotExists(req.params.username);

            // create repo
            let createRepoUrl = server.gogs.url + GOGS_API_PREFIX + `/admin/users/${req.params.username}/repos`;
            let response = yield gogsPost(createRepoUrl, {
                name:    req.params.repositoryName,
                private: true
            });

            if (response.statusCode === 422)
                return next(new Restify.ConflictError(response.body.message ?
                    response.body.message : 'gogs failed to create repository'));

            if (response.statusCode === 201) {
                let repoInfo = extractGogsRepoInfo(response.body);
                repoInfo.password = GenPassword(req.params.username);
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
                username: {isRequired: true, isAlphanumeric: true}
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
                    ret.push(extractGogsRepoInfo(info));
                });
                responseArraySuccess(res, ret);
                return res.end();
            }
            return next(new Restify.ExpectationFailedError(response.body));
        } catch (error) {
            if (error.message === 'invalid gogs admin credential')
                return next(new Restify.InternalServerError(error.message));
            return next(new Restify.InternalServerError(error.message));
        }
    }));

    // get list web hook of an repo
    server.get({
        url: '/repos/:username/:repositoryName/hooks', validation: {
            resources: {
                username:       {isRequired: true, isAlphanumeric: true},
                repositoryName: {isRequired: true, notRegex: /[0-9a-zA-Z\-_]+/g}
            }
        }
    }, Promise.coroutine(function*(req, res, next) {
        try {
            let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks`;
            console.log('repoWebHookUrl', repoWebHookUrl);
            let password = GenPassword(req.params.username);

            let response = yield gogsGet(repoWebHookUrl, req.params.username, password);

            console.log('response.body', response.statusCode, response.body);
            if (response.statusCode === 200) {
                let ret = [];
                console.log('response.body', response.body);
                response.body.forEach(webHook => {
                    ret.push(extractGogsWebHookInfo(webHook));
                });
                return responseArraySuccess(res, ret);
            }
            return next(new Restify.ExpectationFailedError(response.body));
        } catch (error) {
            if (error.message === 'invalid gogs admin credential')
                return next(new Restify.InternalServerError(error.message));
            return next(new Restify.InternalServerError(error.message));
        }
    }));

    // create web hook
    server.post({
        url: '/repos/:username/:repositoryName/hooks', validation: {
            resources: {
                username:       {isRequired: true, isAlphanumeric: true},
                repositoryName: {isRequired: true, notRegex: /[0-9a-zA-Z\-_]+/g},
                url:            {isRequired: true, isUrl: true},
                secret:         {isRequired: false, notRegex: /[0-9a-zA-Z\-_]+/g},

            }
        }
    }, Promise.coroutine(function*(req, res, next) {
        try {
            let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks`;
            console.log('repoWebHookUrl', repoWebHookUrl);
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

            let response = yield gogsPost(repoWebHookUrl, postData, req.params.username, password);

            console.log('response.body', response.statusCode, response.body);
            if (response.statusCode === 201) {
                res.json(extractGogsWebHookInfo(response.body));
                return res.end();
                // return responseArraySuccess(res, ret);
            }
            return next(new Restify.ExpectationFailedError(response.body));
        } catch (error) {
            if (error.message === 'invalid gogs admin credential')
                return next(new Restify.InternalServerError(error.message));
            return next(new Restify.InternalServerError(error.message));
        }
    }));

    // remove web hook
    server.del({
        url: '/repos/:username/:repositoryName/hooks/:id', validation: {
            resources: {
                username:       {isRequired: true, isAlphanumeric: true},
                repositoryName: {isRequired: true, notRegex: /[0-9a-zA-Z\-_]+/g},
                id:             {isRequired: true, isAlphanumeric: true}
            }
        }
    }, Promise.coroutine(function*(req, res, next) {
        try {
            let repoWebHookUrl = server.gogs.url + GOGS_API_PREFIX + `/repos/${req.params.username}/${req.params.repositoryName}/hooks/${req.params.id}`;
            let password = GenPassword(req.params.username);

            if (req.params.secret) {
                postData.config.secret = req.params.secret;
            }

            let response = yield gogsDel(repoWebHookUrl, req.params.username, password);

            console.log('response.body', response.statusCode, response.body);
            if (response.statusCode === 204) {
                res.json(extractGogsWebHookInfo(response.body));
                return res.end();
            }
            return next(new Restify.ExpectationFailedError(response.body));
        } catch (error) {
            if (error.message === 'invalid gogs admin credential')
                return next(new Restify.InternalServerError(error.message));
            return next(new Restify.InternalServerError(error.message));
        }
    }));

    // edit web hook

    // list, add, remove repo's web-hook
    // list, add, remove collaborator to repo

    // update user enable create web hook
    // PATCH /admin/users/:username
    // var postData = {
    //     login_name:     '',
    //     email:          '',
    //     allow_git_hook: true
    //     // password: ''
    // };

    // DELETE /admin/users/:username


    // Edit a hook
    // PATCH /repos/:username/:reponame/hooks/:id

    // Delete a hook
    // DELETE /repos/:username/:reponame/hooks/:id

    // Add user as a collaborator
    // PUT /repos/:username/:reponame/collaborators/:collaborator
    // permission 	string 	The permission to grant the collaborator. Can be one of read, write and admin. Default is write. Read details on forum

    // Create a new repository
    // POST /admin/users/:username/repos

    // private 	bool 	Either true to create a private repository, or false to create a public one. Default is false
    // name 	string 	Required The name of the repository

};
