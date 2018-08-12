use std::collections::HashMap;

use serde_json;

pub struct FormatError;

#[derive(Serialize, Deserialize)]
pub struct Passwd<'a> {
    pub name:       &'a str,
    pub passwd:     &'a str,
    pub uid:        u32,
    pub gid:        u32,
    pub gecos:      &'a str,
    pub dir:        &'a str,
    pub shell:      &'a str,
}

impl<'a> Passwd<'a> {
    pub fn from_line(line: &'a str) -> Result<Passwd<'a>, FormatError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(FormatError);
        }
        let p = Passwd{
            name:   fields[0],
            passwd: fields[1],
            uid:    fields[2].parse::<u32>().map_err(|_| FormatError)?,
            gid:    fields[3].parse::<u32>().map_err(|_| FormatError)?,
            gecos:  fields[4],
            dir:    fields[5],
            shell:  fields[6],
        };
        Ok(p)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Adjunct<'a> {
    pub name:       &'a str,
    pub passwd:     &'a str,
}

impl<'a> Adjunct<'a> {
    pub fn from_line(line: &'a str) -> Result<Adjunct<'a>, FormatError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 2 {
            return Err(FormatError);
        }
        let p = Adjunct{
            name:   fields[0],
            passwd: fields[1],
        };
        Ok(p)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Group<'a> {
    pub name:       &'a str,
    pub passwd:     &'a str,
    pub gid:        u32,
    pub mem:        Vec<&'a str>,
}

impl<'a> Group<'a> {
    pub fn from_line(line: &'a str) -> Result<Group<'a>, FormatError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(FormatError);
        }
        let g = Group{
            name:       fields[0],
            passwd:     fields[1],
            gid:        fields[2].parse::<u32>().map_err(|_| FormatError)?,
            mem:        fields[3].split(',').collect::<Vec<_>>(),
        };
        Ok(g)
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum NumOrText<'a> {
    Number(i64),
    Text(&'a str),
}

/// map_format = "kv"
#[derive(Debug, Serialize)]
pub struct KeyValue<'a>(HashMap<&'a str, NumOrText<'a>>);

impl<'a> KeyValue<'a> {
    pub fn from_line(line: &str) -> Result<KeyValue, FormatError> {
        let mut hm = HashMap::new();
        for kv in line.split_whitespace() {
            let mut w = kv.splitn(2, '=');
            let k = w.next().unwrap();
            let v = w.next().unwrap_or("");
            if let Ok(n) = v.parse::<i64>() {
                hm.insert(k, NumOrText::Number(n));
            } else {
                hm.insert(k, NumOrText::Text(v));
            }
        }
        Ok(KeyValue(hm))
    }
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum StringOrMap<'a> {
    String(&'a str),
    Map(HashMap<&'a str, &'a str>),
}

/// map_format = "fields"
/// map_args = { field = "5", name = "gecos", separator = " " }
/// map_args = { 1 = "email", 2 = "username", separator = " " }
#[derive(Debug, Serialize)]
pub struct Fields<'a>(StringOrMap<'a>);

impl<'a> Fields<'a> {
    pub fn from_line(line: &'a str, args: &'a Option<HashMap<String, String>>) -> Result<StringOrMap<'a>, FormatError> {
        let mut separator = " ";
        let mut field = 0;
        let mut name = "";
        if let Some(args) = args.as_ref() {
            separator = args.get("separator").map(|s| s.as_str()).unwrap_or(separator);
            field = args.get("field").and_then(|c| c.parse::<usize>().ok()).unwrap_or(0);
            name = args.get(name).map(|s| s.as_str()).unwrap_or(name);
        }

        let separator = separator.chars().nth(0).unwrap_or(' ');
        let fields = if separator == ' ' {
            line.split_whitespace().collect::<Vec<_>>()
        } else {
            line.split(separator).collect::<Vec<_>>()
        };

        // field set, and no name: return simple string.
        if field > 0 && name == "" {
            if field > fields.len() {
                return Err(FormatError);
            }
            return Ok(StringOrMap::String(fields[field - 1]));
        }

        // build a map.
        let mut hm = HashMap::new();
        if field > 0 && name != "" && field <= fields.len() {
            // insert field "field" as "name"
            hm.insert(name, fields[field - 1]);
        }
        if let Some(args) = args.as_ref() {
            // insert fields by number.
            for num in args.keys() {
                if let Ok(n) = num.parse::<usize>() {
                    if n > 0 && n <= fields.len() {
                        hm.insert(&args[num], fields[n - 1]);
                    }
                } else {
                    if num != "name" && num != "field" && num != "separator" {
                        hm.insert(num.as_str(), &args[num]);
                    }
                }
            }
        }

        Ok(StringOrMap::Map::<'a>(hm))
    }
}

pub fn line_to_json(line: &str, format: &str, args: &Option<HashMap<String, String>>) -> Result<serde_json::Value, FormatError> {
    match format {
        "passwd"            => serde_json::to_value(&Passwd::from_line(line)?).map_err(|_| FormatError),
        "group"             => serde_json::to_value(&Group::from_line(line)?).map_err(|_| FormatError),
        "adjunct"           => serde_json::to_value(&Adjunct::from_line(line)?).map_err(|_| FormatError),
        "kv"                => serde_json::to_value(&KeyValue::from_line(line)?).map_err(|_| FormatError),
        "fields"            => serde_json::to_value(&Fields::from_line(line, args)?).map_err(|_| FormatError),
        "json"              => serde_json::from_str(line).map_err(|_| FormatError),
        _                   => Err(FormatError),
    }
}

