
LUA API
=======

A Lua function call be called for authentication, or map lookup.

Webnis library
--------------

There is a `webnis` library that is imported by default that contains
functions to do map lookups and authentication. The functions are:

```
let result = webnis.map_lookup(request, mapname, keyname, keyvalue)
```
Looks up the `keyname`/`keyvalue` pair (e.g. user=exampleuser) in the map `mapname`.
The return value is the result of the lookup or nil if it failed.

```
let result = webnis.map_auth(request, mapname, keyname)
```
Looks up the `keyname`/`request.username` pair in the map `mapname`. If
present, and the returned object has a member `password`, `request.password`
is checked against that.

Authentication
--------------

```
result = auth_function(request)
returnobject,status = auth_function(request)
```
The passed in `request` table contains an `request.username` and an
`request.password`. These are the username/password query parameters passed
in in the POST body of the request.  It also contains an `request.domain`
value which is the webnis domain for this request.  Any additional query
parameters are also available (for example, "service" or "remote").

Return value
------------

You can simply return a `table` on success, it will be turned into a JSON object,
and returned wrapped in another JSON object as the `result`: parameter. This is
the format that `webnis-bind` expects.

Return **nil** to indicate "lookup failed". It will result in an error object
being returned as response.

If you want to have more control, you can return `table, status`. `table` will
be turned into JSON and output as-is, with the HTTP status set to `status`.

Map lookups
-----------

```
result = lookup_function(request)
```

The `request` argument contains a `request.keyname` and a `request.keyvalue`.
You usually use `webnis.map_lookup()` with these.

Return value
------------

You return a `table` on success, which will be turned into a JSON object,
and returned wrapped in another JSON object as the `result`: parameter. This is
the format that `webnis-bind` expects.

Return nil on failure.

