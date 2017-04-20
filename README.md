### Tính năng

1. tao new website tren db Thanh`
2. new repos tren gitea (migration tu 1 template)
3. new cloudflare subdomain
4. new virtual host
5. la call init qua ben ms-site-build
6. sẽ nằm cùng vps với ms-site-build

### Run parameters
`node index.js --host=0.0.0.0 --port=7000 --gogsUsername=root --gogsPassword=pass --gogsUrl=http://127.0.0.1:3000`
* `host` network interface app will listening to, default to `127.0.0.1` (Required)
* `port` local listening port (Required)
* `gogsUsername` gogs server admin username (Required)
* `gogsPassword` gogs server admin password (Required)
* `gogsUrl` gogs server access url (Required)

### Alternative config environent variable
`SERVER_HOST, SERVER_PORT, GOGS_USERNAME, GOGS_PASSWORD, GOGS_URL`

### REST API
* http status code khác 200 là lỗi, response body
```
{
    "code": "InvalidArgument",
    "message": "An Error Message"
}
```

#### Create repository `POST` `/repos`
##### JSON post data
```
{
    "username": "user",
    "repositoryName": "myRepo" // valid char: 0-9 a-z A-Z - _
}
```
#### Response
```
{
    "id": 1,
    "fullName": "user/myRepo",
    "url": "http://127.0.0.1:3000/user/myRepo",
    "private": true,
    "username": "user",
    "password": "lcvjoasdjoasdjifkasdjflasjdfl" // repository password == username's gogs password
}
```

#### New repository migrate from template `POST` `/migration`
##### JSON post data
```
{
    "username": "user",
    "templateName": "template-name", // template repository name from 'templates' account
    "repositoryName": "myRepo" // valid char: 0-9 a-z A-Z - _
}
```
#### Response
```
{
	"id": 22,
	"name": "pillar-clone",
	"fullName": "quantri/pillar-clone",
	"url": "http://localhost:3000/quantri/pillar-clone.git",
	"private": true,
	"username": "newUser",
	"password": "b03ecb72deb6c8qweqee2e21aa66cf6ab38ff0ba10353f329cb6d59513c433"
}
```

#### Get username's repositories `GET` `/repos/:username`
```
{
    "data":         data, // array of respository info (like response of create repository)
    "recordsTotal": data.length
}
```

#### Create WeHook to repository `POST` `/repos/:username/:repositoryName/hooks`
##### JSON post data
```
    "url": "http://deploy.server/project/hook",
    "secret": "bat-mi"
```
##### Response
```
{
    "id":          1,
    "url":         "http://deploy.server/project/hook",
    "contentType": "json",
    "active":      true
}
```

#### Edit WeHook to repository `PATCH` `/repos/:username/:repositoryName/hooks/:webHookId`
##### JSON post data
```
    "url": "http://deploy.server/project/hook",
    "secret": "bat-mi",
    "active": false
```
##### Response
```
{
    "id":          1,
    "url":         "http://deploy.server/project/hook",
    "contentType": "json",
    "active":      false
}
```

#### Delete WebHook of repository `DELETE` `/repos/:username/:repositoryName/hooks/:webHookId`
##### Response nothing
