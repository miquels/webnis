
# libnss-webnis

NSS module for Linux that gets user/group info from an HTTP server.

The NSS module itself does not actually speak HTTP. It connects over
a local UNIX socket to the webnisd daemon, and it talks a
simple line-based protocol on that socket. The webnisd daemon
is responsible for connecting to the HTTP backend server,
sending the request , and receiving/decoding the JSON response.

The line based protocol between the module and webnisd is like:

```
>> GETPWNAM mikevs
<< 200 mikevs:x:1000:1000:Mike:/home/mikevs:

>> GETGROUPIDS mikevs
<< 200 mikevs:50,1000

>> GETPWNAM torvalds
>> 404 Not Found
```

## Previous work

This module got a lot of its inspiration from
[libnss-aad by Outlook](https://github.com/outlook/libnss-aad)

