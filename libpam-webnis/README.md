
# libpam-webnis

PAM module for Linux that authenticates against a HTTP server.

The PAM module itself does not actually speak HTTP. It connects over
a local UNIX socket to the webnisd daemon, and it talks a
simple line-based protocol on that socket. The webnisd daemon
is responsible for connecting to the HTTP backend server,
sending the request , and receiving/decoding the JSON response.

The line based protocol between the module and webnisd is like:

```
>> PAM 1.0
>> SET remotehost=1.2.3.4
>> AUTH mikevs password
<< 200 OK
```

