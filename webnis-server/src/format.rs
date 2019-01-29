use regex::Regex;
use std::collections::HashMap;
use std::str::FromStr;

use serde::{self, Deserialize, Deserializer};
use serde_json;

use crate::errors::*;

#[derive(Serialize, Deserialize)]
pub struct Passwd<'a> {
    pub name:   &'a str,
    pub passwd: &'a str,
    pub uid:    u32,
    pub gid:    u32,
    pub gecos:  &'a str,
    pub dir:    &'a str,
    pub shell:  &'a str,
}

impl<'a> Passwd<'a> {
    pub fn from_line(line: &'a str) -> Result<Passwd<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 7 {
            return Err(WnError::DeserializeData);
        }
        let p = Passwd {
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
    pub name:   &'a str,
    pub passwd: &'a str,
}

impl<'a> Adjunct<'a> {
    pub fn from_line(line: &'a str) -> Result<Adjunct<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() < 2 {
            return Err(WnError::DeserializeData);
        }
        let p = Adjunct {
            name:   fields[0],
            passwd: fields[1],
        };
        Ok(p)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Group<'a> {
    pub name:   &'a str,
    pub passwd: &'a str,
    pub gid:    u32,
    pub mem:    Vec<&'a str>,
}

impl<'a> Group<'a> {
    pub fn from_line(line: &'a str) -> Result<Group<'a>, WnError> {
        let fields = line.split(':').collect::<Vec<_>>();
        if fields.len() != 4 {
            return Err(WnError::DeserializeData);
        }
        let g = Group {
            name:   fields[0],
            passwd: fields[1],
            gid:    fields[2].parse::<u32>().map_err(|_| WnError::DeserializeData)?,
            mem:    fields[3].split(',').collect::<Vec<_>>(),
        };
        Ok(g)
    }
}

// A number or a string.
#[derive(Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum NumOrText<'a> {
    Number(i64),
    Text(&'a str),
}

// Parse a value into the number or string variant.
impl<'a> NumOrText<'a> {
    fn parse(val: &'a str) -> NumOrText<'a> {
        match val.parse::<i64>() {
            Ok(v) => NumOrText::Number(v),
            Err(_) => NumOrText::Text(val),
        }
    }
}

/// map_format = "key-value"
#[derive(Debug, Serialize)]
pub struct KeyValue<'a>(HashMap<&'a str, NumOrText<'a>>);

impl<'a> KeyValue<'a> {
    pub fn from_line(
        line: &'a str,
        output: &'a Option<HashMap<String, String>>,
    ) -> Result<KeyValue<'a>, WnError>
    {
        // first split on whitespace, which gives us a bunch of
        // key=value items. Then split those on '=' and put them
        // into a HashMap.
        let mut hm = HashMap::new();
        for kv in line.split_whitespace() {
            let mut w = kv.splitn(2, '=');
            let k = w.next().unwrap();
            let v = w.next().unwrap_or("");
            hm.insert(k, NumOrText::parse(v));
        }

        // no output mapping? then we're done.
        if output.is_none() {
            return Ok(KeyValue(hm));
        }

        // apply output mapping.
        lazy_static! {
            // matches { (ident) (:modifier) }
            // modifier is ignored for now
            static ref RE: Regex = Regex::new(r"^\{([0-9a-zA-Z_-]+)(:[a-z])?\}$").unwrap();
        }

        let mut res = HashMap::new();

        // apply output format. result goes into "res".
        for (k, v) in output.as_ref().unwrap().iter() {
            // interpolate 'v'. so replace {field} with the corresponding field.
            let nv = if let Some(caps) = RE.captures(v) {
                if let Some(val) = hm.remove(&caps[1]) {
                    val
                } else {
                    continue;
                }
            } else {
                NumOrText::Text(v.as_str())
            };
            // and insert into output hashmap.
            res.insert(k.as_str(), nv);
        }
        Ok(KeyValue(res))
    }
}

pub struct Fields;

impl Fields {
    // This could be a free-standing function. It's defined as Fields::from_line() only
    // to have parity with the other from_line methods.
    pub fn from_line<'a>(
        line: &'a str,
        output: &'a Option<HashMap<String, String>>,
        separator: &str,
    ) -> Result<HashMap<NumOrText<'a>, NumOrText<'a>>, WnError>
    {
        // split line into parts.
        let separator = separator.chars().nth(0).unwrap_or('\0');
        let fields = if separator == '\0' {
            line.split_whitespace().collect::<Vec<_>>()
        } else {
            line.split(separator).collect::<Vec<_>>()
        };

        // no output mapping, return hashmap keyed by the index number, starting at 1.
        // { 1 => "name", 2 => "passwd", 3 => uid, ... }
        if output.is_none() {
            let res = fields
                .into_iter()
                .enumerate()
                .map(|(num, val)| (NumOrText::Number((num + 1) as i64), NumOrText::parse(val)))
                .collect::<HashMap<_, _>>();
            return Ok(res);
        }

        // apply output mapping.
        lazy_static! {
            // matches { (index) (:modifier) }
            // modifier is ignored for now
            static ref RE: Regex = Regex::new(r"^\{([0-9]+)(:[a-z])?\}$").unwrap();
        }

        let mut hm = HashMap::new();

        // apply output format. result goes into "hm".
        for (k, v) in output.as_ref().unwrap().iter() {
            // interpolate 'v'. so replace {1}, {2} etc with the corresponding field.
            let mut nv = v.as_str();
            if let Some(caps) = RE.captures(v) {
                if let Ok(n) = caps[1].parse::<usize>() {
                    if n > 0 && n <= fields.len() {
                        nv = fields[n - 1];
                    }
                }
            }
            // and insert into output hashmap.
            hm.insert(NumOrText::Text(k), NumOrText::parse(nv));
        }
        Ok(hm)
    }
}

// helper.
fn to_json<T: serde::Serialize>(value: T) -> Result<serde_json::Value, WnError> {
    serde_json::to_value(value).map_err(WnError::SerializeJson)
}

#[derive(Debug, Clone, Deserialize)]
pub enum Format {
    Passwd,
    Group,
    Adjunct,
    KeyValue,
    ColSep,
    WsSep,
    TabSep,
    Line,
    Json,
}

impl FromStr for Format {
    type Err = WnError;

    fn from_str(s: &str) -> Result<Format, WnError> {
        let f = match s {
            "passwd" => Format::Passwd,
            "group" => Format::Group,
            "adjunct" => Format::Adjunct,
            "key-value" => Format::KeyValue,
            "colon-separated" => Format::ColSep,
            "whitespace-separated" => Format::WsSep,
            "tab-separated" => Format::TabSep,
            "line" => Format::Line,
            "json" => Format::Json,
            _ => return Err(WnError::UnknownFormat),
        };
        Ok(f)
    }
}

// Serde helper
pub fn option_deserialize_format<'de, D>(deserializer: D) -> Result<Option<Format>, D::Error>
where D: Deserializer<'de> {
    let s = String::deserialize(deserializer)?;
    Format::from_str(&s)
        .map(|f| Some(f))
        .map_err(serde::de::Error::custom)
}

pub fn line_to_json(
    line: &str,
    format: &Format,
    output: &Option<HashMap<String, String>>,
) -> Result<serde_json::Value, WnError>
{
    match format {
        Format::Passwd => to_json(&Passwd::from_line(line)?),
        Format::Group => to_json(&Group::from_line(line)?),
        Format::Adjunct => to_json(&Adjunct::from_line(line)?),
        Format::KeyValue => to_json(&KeyValue::from_line(line, output)?),
        Format::ColSep => to_json(&Fields::from_line(line, output, ":")?),
        Format::WsSep => to_json(&Fields::from_line(line, output, "")?),
        Format::TabSep => to_json(&Fields::from_line(line, output, "\t")?),
        Format::Line => to_json(&Fields::from_line(line, output, "\n")?),
        Format::Json => serde_json::from_str(line).map_err(WnError::SerializeJson),
    }
}
