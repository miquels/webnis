use std::collections::HashMap;

use serde_json;
use serde;

use crate::errors::*;

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
    pub fn from_line(line: &'a str) -> Result<Passwd<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(WnError::DeserializeData);
        }
        let p = Passwd{
            name:   fields[0],
            passwd: fields[1],
            uid:    fields[2].parse::<u32>().map_err(|_| WnError::DeserializeData)?,
            gid:    fields[3].parse::<u32>().map_err(|_| WnError::DeserializeData)?,
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
    pub fn from_line(line: &'a str) -> Result<Adjunct<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 2 {
            return Err(WnError::DeserializeData);
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
    pub fn from_line(line: &'a str) -> Result<Group<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(WnError::DeserializeData);
        }
        let g = Group{
            name:       fields[0],
            passwd:     fields[1],
            gid:        fields[2].parse::<u32>().map_err(|_| WnError::DeserializeData)?,
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
    pub fn from_line(line: &str) -> Result<KeyValue, WnError> {
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
    pub fn from_line(line: &'a str, args: &'a Option<HashMap<String, String>>) -> Result<StringOrMap<'a>, WnError> {
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
                return Err(WnError::DeserializeData);
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

fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, WnError> {
    serde_json::to_value(value).map_err(WnError::SerializeJson)
}

pub fn line_to_json(line: &str, format: &str, args: &Option<HashMap<String, String>>) -> Result<serde_json::Value, WnError> {
    match format {
        "passwd"            => to_json(&Passwd::from_line(line)?),
        "group"             => to_json(&Group::from_line(line)?),
        "adjunct"           => to_json(&Adjunct::from_line(line)?),
        "kv"                => to_json(&KeyValue::from_line(line)?),
        "fields"            => to_json(&Fields::from_line(line, args)?),
        "json"              => serde_json::from_str(line).map_err(WnError::SerializeJson),
        _                   => Err(WnError::UnknownFormat),
    }
}

