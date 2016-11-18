'use strict';

const Request = require('request-promise');
const Promise = require('bluebird');
const Path = require('path');

const GOGS_SESSION_HEADER_KEY = 'i_like_gogits';
// class GogsClient {
//     constructor(serverUrl) {
//         this.
//     }
//
//     *(username, password) {
//
//     };
//
//     get(urlPath) {
//
//     }
//
//     post(urlPath, data) {
//
//     }
// }

module.exports = function (serverUrl) {
    if (serverUrl.endsWith('/')) {
        serverUrl = serverUrl.slice(0, serverUrl.length - 1); // trim last /
    }
    return {
        getToken: Promise.coroutine(function*(username, password) {
            // get login page string
            console.log('url', serverUrl + '/user/login');
            let loginUrl = serverUrl + '/user/login';

            let loginPageBody = yield Request({
                method: 'GET',
                uri:    loginUrl,
                jar:    true
            });
            // get csrf token from login page body string
            let matches = (/_csrf" value="(.+)"/g).exec(loginPageBody);
            if (!matches || matches.length != 2)
                throw new Error('csrf token not found');
            let csrfToken = matches[1];

            let postData = {
                _csrf:     csrfToken,
                user_name: username,
                password:  password,
                remember:  'on'
            };

            let resp = yield Request({
                method:                  'POST',
                uri:                     loginUrl,
                form:                    postData,
                resolveWithFullResponse: true
            });
            // TODO check case login fail
            console.log('post login resp body', resp.body);
            resp.headers['set-cookie'].some(headerStr => {
                if (!headerStr.startsWith('_csrf')) return false;
                csrfToken = headerStr.slice(6, headerStr.indexOf(';'));
                return true;
            });

            // create access token http://localhost:3000/user/settings/applications
            // post _csrf:5M_XH3wNKiUFOtDr9htH_Qbr5rI6MTQ3OTI4NTQ1MDAwMTQ3MjAwMA==
            // name:token2

            console.log('csrfToken', csrfToken, resp.headers);


            // create access token

            // post login and get token
        })
    };
};
