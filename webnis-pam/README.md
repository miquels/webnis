
# webnis-pam

PAM module for Linux that authenticates against a HTTP server.

The PAM module itself does not actually speak HTTP. It connects over
a local UNIX socket to the webnis-bind daemon, and it talks a
simple line-based protocol on that socket. The webnis-bind daemon
is responsible for connecting to the HTTPS backend server,
sending the request , and receiving/decoding the JSON response.

The line based protocol between the module and webnis-bind is like:

```
>> SET service=webnis
>> SET remotehost=1.2.3.4
>> AUTH mikevs password
<< 200 OK
```
Note that the `password` needs to be percent-encoded.

TODO
----

The SET name=value part is not yet implemented. We should use this
to forward the PAM\_SERVICE and PAM\_RHOST items to the webnis server.

