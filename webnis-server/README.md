
# webnis-server

This is a HTTPS server that does two things. It serves simple key/value
maps, and it can be used as an authentication server (against the
data in those maps).

It understands Gdbm and Json map types, and the data in those maps
can be in serveral formats such as json, key/value, whitespace-separated
or colon-separated, etc. So it can use NIS maps from /var/yp
directly (with a bit of configuration).

There's also a lua maptype. A lookup in a lua map calls a lua function
that can gather data from multiple different sources.

The data from the maps is always served in JSON output format, no matter
what format the source map is in.

# protocol

The request to the webnis server is a simple HTTPS request, like:

```
GET /webnis/my.domain/map/passwd?name=mikevs
HTTP/1.1 200 OK
Content-Type: application/json

{"result":{"home":"/home/mikevs","gecos":"","gid":1000,"passwd":"x","shell":"/bin/sh","uid":1000,"username":"mikevs"}}
```

As you can see the reply format is loosely based on JSONRPC.

A couple of examples (you can define as many maps as you like):

```
GET <BASE>/<DOMAIN>/map/passwd?username=<name>
GET <BASE>/<DOMAIN>/map/passwd?uid=<number>
GET <BASE>/<DOMAIN>/map/group?group=<name>
GET <BASE>/<DOMAIN>/map/group?gid=<number>
GET <BASE>/<DOMAIN>/map/gidlist?username=<name>
POST <BASE>/<DOMAIN>/auth
```

For auth you need to send a `x-www-form-urlencoded` body with
`username` and `password` parameters, example:

```
POST /webnis/my.domain/auth
Content-Length: 35
Content-Type: application/x-www-form-urlencoded

username=testuser&password=testpass

HTTP/1.1 200 OK
Content-Type: application/json

{"result":{"some_json":true}}
```

You can also send a JSON object with `username` and `password` parameters.
You need to set `Content-Type: application/json` header for that.

Advantage of x-www-form-urlencoded is that the password does not _have_
to be in UTF-8 encoding, it is handled as a stream of bytes, which can be
useful in legacy environments.

