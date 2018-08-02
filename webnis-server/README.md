
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
GET BASE/passwd?name=<name>
GET BASE/passwd?uid=<number>
GET BASE/group?name=<name>
GET BASE/group?gid=<number>
GET BASE/gidlist?name=<name>
```

To be implemented:
```
POST BASE/auth
     body params: name,passwd
```

