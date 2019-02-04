
# webnis-bind

This is a daemon that sits between webnis-nss and webnis-pam and the
webnis server that has the webnis data.

It accepts requests like GETPWNAM <name>, GETGRGID <number>. It translates
that to a URL on a webnis server, goes out on the net to retrieve the data,
and returns it to the local client on the UNIX socket.

The advantages of using a daemon instead of letting
libnss-webnis.so.2/pam-webnis.so connect to a webnis server directly are:

- can keep SSL connections alive so it doesn't have to reconnect all the time
- can loadbalance over a set of servers, and detect dead servers.
- can authenticate with the remote server
- can detect the requesting process' UID/GID using SO_PEERCRED on the
  UNIX socket, and restrict what requests a client can do

# protocol

On the local unix socket the protocol is line-based. A session looks like:

```
GETPWNAM mikevs
200 mikevs:x:1000:1000:Mike:/home/mikevs:
```

Try it yourself using:
```
nc -N -U /var/run/webnis-bind.sock
```
(Control-C or Control-D will exit)

The request to the webnis server is a simple HTTPS request, like:

```
GET /.well-known/webnis/default/map/passwd?name=mikevs
HTTP/1.1 200 OK
Content-Type: application/json

{"result":{"dir":"/home/mikevs","gecos":"Mike","gid":1000,"passwd":"x","shell":"","uid":1000,"user":"mikevs"}}
```

The translation from JSON to unix-flavored colon-separated-values is so
that clients can easily parse it without including 1MB of
serde/serde_json library code (however, this might change - I recently
discovered the [json crate](https://crates.io/crates/json) which is much smaller).

Try it yourself:
```
curl -i https://<WEBNISSERVER>/.well-known/webnis/default/map/passwd?name=stuser
```

Currently implemented are:

```
GETPWNAM <name>				GET <BASE>/<DOMAIN>/map/passwd?name=<name>
GETPWUID <uid>				GET <BASE>/<DOMAIN>/map/passwd?uid=<number>
GETGRNAM <name>				GET <BASE>/<DOMAIN>/map/group?name=<name>
GETGRGID <gid>				GET <BASE>/<DOMAIN>/map/group?gid=<number>
GETGIDLIST <name>			GET <BASE>/<DOMAIN>/map/gidlist?name=<name>
AUTH <name> <passwd> [service] [remote]	POST <BASE>/<DOMAIN>/auth
```

`<BASE>` defaults to `/.well-known/webnis`, and `<DOMAIN>` defaults to .... `default`.

The `<passwd>` in AUTH needs to be percent-encoded by the client.

Service and remote are optional. Service is the name of the service querying the
webnis server. Webnis-pam sets this to the PAM service. Remote is the remote
IP address of a client, with an optional :port, If that is applicable. So without
a port for IPv4 and IPv6 respectively: **192.168.158.23**, **2001:db8:42::2**.
With a port: **192.168.158.23:2884**, **[2001:db8:42::2]:2884** .

