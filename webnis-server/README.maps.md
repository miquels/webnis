
# Map types and formats

The server supports several map types and formats.

## Map types (type = "....")

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

## Map formats (format = "....")

A GDBM lookup returns a blob of data. This data is in a certain format-
by setting the *format* option in the map definition you tell the server
how to interpret that data.

### json
  The data is in json format and will be served as-is.

### passwd
  7 colon-separated fields in /etc/passwd format. The Fields are mapped to
  `name`, `passwd`, `uid`, `gid`, `gecos`, `dir`, `shell`.

### group
  4 colon-separated fields in /etc/passwd format. The fields are mapped to
  `name`, `passwd`, `gid`, `mem` where `mem` is an array.

### adjunct
  \>=2 colon-separated fields in /etc/passwd format. The first two fields
  are mapped to `name`, `passwd`, the rest is ignored.

### key-value
  Simple json-like key/value. Example: `name=joop uid=2020 dir=/tmp shell=/bin/sh`.
  There are no types, and no quoting/escaping of values. The key/value pairs are
  put into a JSON object. Values that look like a number will be JSON numbers,
  other values will be JSON quoted strings.

### colon-separated
  A line with fields separated by a colon (":"). Each value will be put into
  a JSON object, keyed by the index of the field, starting at 1.

### tab-separated
  A line with fields separated by a tab ("\t).

### whitespace-separated
  A line with fields separated by any amount of whitespace (spaces or tabs).

## Map output formats (output = "....")

The output can be transformed by defining an *output* setting. That setting is
a TOML map. The keys in that map are the keys of the output object, the values
are interpolated from the values in the TOML map.

Values like {1}, {2} etc map to the values from a \*-separated map. Values like
{name}, {uid} map to values from a key-value map.

For example, this is requivalent to the *passwd* format:

```
 format = "colon-separated"
 output = { name = "{1}", passwd = "{2}", uid = "{3}", gid = "{4}", gecos = "{5}", dir = "{6}", shell = "{7}" }
```

