
# webnis-bind

This is a daemon that sits between libnss-webnis and libpam-webnis and the
webnis server that has the webnis data.

It accepts requests like GETPWNAM <name>, GETGRGID <number>. It translates
that to a URL on a webnis server, goes out on the net to retrieve the data,
and returns it to the local client on the UNIX socket.

The advantage of using a daemon instead of letting
libnss-webnis/libpam-webnis connect to a webnis server directly are:

- can keep SSL connections alive so it doesn't have to reconnect all the time
- can loadbalance over a set of servers, and detect dead servers.
- can authenticate with the remote server
- can detect the requesting process' UID/GID using SO_PEERCRED on the
  UNIX socket, and restrict what requests a client can do

# protocol

On the local unix socket the protocol is line-based. A session looks like:

>> GETPWNAM mikevs
<< {"result":{"dir":"/home/mikevs","gecos":"","gid":1000,"passwd":"x","shell":"/bin/sh","uid":1000,"user":"mikevs"}}

The request to the webnis server is a simple HTTPS request, like:

GET /webnis/passwd?name=mikevs
200 Ok
{"result":{"dir":"/home/mikevs","gecos":"","gid":1000,"passwd":"x","shell":"/bin/sh","uid":1000,"user":"mikevs"}}

As you can see the reply is the same in both cases. The format is
loosely based on JSONRPC.

Currently implemented are:

GETPWNAM <name>		GET BASE/passwd?name=<name>
GETPWUID <uid>		GET BASE/passwd?uid=<number>
GETGRNAM <name>		GET BASE/group?name=<name>
GETGRGID <gid>		GET BASE/group?gid=<number>
GETGIDLIST <name>	GET BASE/gidlist?name=<name>

To be implemented:
AUTH <name> <passwd>	POST BASE/auth
			body params: name,passwd

