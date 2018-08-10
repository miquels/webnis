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

pub fn line_to_json(line: &str, format: &str) -> Result<serde_json::Value, FormatError> {
    match format {
        "passwd"    => serde_json::to_value(&Passwd::from_line(line)?).map_err(|_| FormatError),
        "group"     => serde_json::to_value(&Group::from_line(line)?).map_err(|_| FormatError),
        "adjunct"   => serde_json::to_value(&Adjunct::from_line(line)?).map_err(|_| FormatError),
        "kv"        => serde_json::to_value(&KeyValue::from_line(line)?).map_err(|_| FormatError),
        "json"      => serde_json::from_str(line).map_err(|_| FormatError),
        _           => Err(FormatError),
    }
}

