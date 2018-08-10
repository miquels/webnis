
# Webnis

It's the 21st century. NIS (if you're really old, YP) is dead, but somehow
people keep using it. Why? Because it's simple and does the job. So why
not replace it with something that is even simpler and uses more recent
technologies like those from the first few years of this century. Well,
that's selling it short - the technologies are not cutting edge, but
it _is_ all written in Rust!.

Webnis contains:

## [webnis-server](webnis-server/)

A simple HTTPS server that serves gdbm / json maps indexed by a key.
It can in fact serve existing NIS maps from /var/yp/<domain>. It can
also do authentication by looking up username/password in one of those
maps and verifying the password using pwhash::unix::verify().

## [webnis-nss](webnis-nss/)

A NSS module (libnss_webnis.so.2) that does passwd/group lookups via webnis (using webnis-bind).

## [webnis-pam](webnis-pam/)

A PAM module (pam_webnis.so) that authenticates via webnis (using webnis-bind).

## [webnis-bind](webnis-bind/)

A daemon that sits between the webnis-server and webnis-pam/webnis-nss.
It checks which servers are alive, does reconnects, keeps a connection
pool open, etc. Clients talk to the daemon over a Unix socket.

## webnis-utils

Soon! This will contain wncat, wnmatch, wnwhich.

