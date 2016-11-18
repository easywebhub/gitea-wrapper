'use strict';

const Promise = require('bluebird');
const Fs = Promise.promisifyAll(require('fs'));

class TokenStore {
    constructor(filePath) {
        this.filePath = filePath;
        try {
            this.data = JSON.parse(Fs.readFileSync(filePath).toString());
        } catch (ex) {
            console.log('read token store failed', ex.message);
            this.data = {
                admin: '',
                user:  {}
            };
        }
    }

    get adminToken() {
        return this.data.admin;
    }

    set adminToken(token) {
        if (token && typeof(token) === 'string') {
            this.data.admin = token;
        }
    }

    getUserToken(username) {
        return this.user[username];
    }

    setUserToken(username, token) {
        this.user[username] = token;
    }

    save() {
        return Fs.writeFileAsync(this.filePath, this.data);
    }
}

module.exports = TokenStore;
