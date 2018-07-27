
# Webnis

It's the 21st century. NIS (if you're really old, YP) is dead, but somehow
people keep using it. Why? Because it's simple and does the job. So why
not replace it with something that is even simpler and uses more recent
technologies like those from the first few years of this century. Well,
that's selling it short - the technologies are not cutting edge, but
it _is_ all written in Rust!.

Webnis contains:

## webnis-server

A simple HTTPS server that serves gdbm / json maps indexed by a key.
It can in fact serve existing NIS maps from /var/yp/<domain>.

## libnss-webnis

A NSS module that does passwd/group lookups via webnis (using webnis-bind).

## libpam-webnis

A PAM module that authenticates via webnis (using webnis-bind).

## webnis-bind

A daemon that sits between the webnis-server and libpam-webnis/libnss-webnis.
It checks which servers are alive, does reconnects, keeps a connection
pool open, etc. Clients talk to the daemon over a Unix socket.

