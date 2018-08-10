
# webnis-server

This is a HTTPS server that servers password and group data. Currently
it simply uses .db maps from the /var/yp/<nisdomain> directory.

# protocol

The request to the webnis server is a simple HTTPS request, like:

```
GET /webnis/passwd?name=mikevs
HTTP/1.1 200 OK
Content-Type: application/json

{"result":{"dir":"/home/mikevs","gecos":"","gid":1000,"passwd":"x","shell":"/bin/sh","uid":1000,"user":"mikevs"}}
```

As you can see the reply format is loosely based on JSONRPC.

Currently implemented are:

```
GET <BASE>/<DOMAIN>/map/passwd?name=<name>
GET <BASE>/<DOMAIN>/map/passwd?uid=<number>
GET <BASE>/<DOMAIN>/map/group?name=<name>
GET <BASE>/<DOMAIN>/map/group?gid=<number>
GET <BASE>/<DOMAIN>/map/gidlist?name=<name>
POST <BASE>/<DOMAIN>/auth
```

For auth you need to send a `x-www-form-urlencoded` body with
`username` and `password` parameters.
