
# Map types and formats

The server supports several map types and formats.

## Map types (map_type)

### gdbm
  This is a simple key/value map. The map has only one, unnamed primary key.
  Multiple lookup keys are supported by simply having the same data in
  a second gdbm file with a different primary key.

### json
  An array of json objects. Multiple keys are supported; any object can be
  found by looking up one of its members. This file is kept in-memory and
  lookups are done sequentially by iterating over every object, so it
  should not be too big.

### lua
  A lua function, defined in a lua script.

## Map formats (map_format)

### json
  Maps in json format are served as-is.

### kv
  Simple json-like key/value. Example: `name=joop uid=2020 dir=/tmp shell=/bin/sh`.
  There are no types, and no quoting/escaping of values.

### passwd
  7 colon-separated fields in /etc/passwd format. The Fields are mapped to
  `name`, `passwd`, `uid`, `gid`, `gecos`, `dir`, `shell`.

### group
  4 colon-separated fields in /etc/passwd format. The fields are mapped to
  `name`, `passwd`, `gid`, `mem` where `mem` is an array.

### adjunct
  \>=2 colon-separated fields in /etc/passwd format. The first two fields
  are mapped to `name`, `passwd`, the rest is ignored.

### fields
  A line with fields separated by whitespace. The field mapping is determined
  by the `map_args` setting, which can be in a few forms:

- `{ field = "2" }` -- the Json reply is the value of the second field (string or number).
- `{ field = "5", name = "gecos" }` -- the json reply is an object with one member, `gecos`,
  and the value is that of the fifth field
- `{ 1 = "name", 2 = "passwd", 3 = "uid", 4 = "gid" }` -- a mapping of fields to
  an object with members `name`, `passwd`, `uid` and `gid`.

  If in the args a value "separator" is set, the data will be split with that
  separator instead of whitespace.

  Example for a password format file defined as map_type `field`:
```
[map.passwd.byname]
  key = "name"
  map_type = "gdbm"
  map_format = "fields"
  map_args = { separator = ":", 1 = "name", 2 = "passwd", 3 = "uid", 4 = "gid", 5 = "gecos", 6 = "dir", 7 = "shell" }
  map_file = "passwd.byname"
```
  The `uid` and `gid` members would be output as strings instead of numbers though.

