use std::fmt;

use serde::{Deserialize, Serialize};

/// Dynamic value type crossing the driver/plugin boundary.
///
/// Structured data is data, never code: Lua plugins and JSON-capable
/// appliances both land here without pulling in a Python-like object system.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Value {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Value>),
    Map(indexmap::IndexMap<String, Value>),
}

impl Value {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Int(i) => Some(*i),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_list(&self) -> Option<&[Value]> {
        match self {
            Value::List(l) => Some(l),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Map(m) => m.get(key),
            _ => None,
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Null => write!(f, "null"),
            Value::Bool(b) => write!(f, "{b}"),
            Value::Int(i) => write!(f, "{i}"),
            Value::Float(x) => write!(f, "{x}"),
            Value::Str(s) => write!(f, "{s}"),
            other => write!(f, "{}", serde_json_compat(other)),
        }
    }
}

fn serde_json_compat(v: &Value) -> String {
    // Value is Serialize; this indirection keeps Display free of a hard
    // json dependency in hot paths for scalars.
    serde_json::to_string(v).unwrap_or_else(|_| "<unserializable>".into())
}

/// Ordered parameter map (capability inputs/outputs).
pub type Params = indexmap::IndexMap<String, Value>;

pub trait IntoValue {
    fn into_value(self) -> Value;
}

impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}

impl IntoValue for () {
    fn into_value(self) -> Value {
        Value::Null
    }
}

impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::Bool(self)
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::Int(self)
    }
}

impl IntoValue for u32 {
    fn into_value(self) -> Value {
        Value::Int(self as i64)
    }
}

impl IntoValue for String {
    fn into_value(self) -> Value {
        Value::Str(self)
    }
}

impl IntoValue for &str {
    fn into_value(self) -> Value {
        Value::Str(self.to_owned())
    }
}

impl<T: IntoValue> IntoValue for Vec<T> {
    fn into_value(self) -> Value {
        Value::List(self.into_iter().map(IntoValue::into_value).collect())
    }
}

impl<T: IntoValue> IntoValue for Option<T> {
    fn into_value(self) -> Value {
        match self {
            Some(v) => v.into_value(),
            None => Value::Null,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_scalars_are_bare() {
        assert_eq!(Value::Int(7).to_string(), "7");
        assert_eq!(Value::Str("eth0".into()).to_string(), "eth0");
        assert_eq!(Value::Bool(true).to_string(), "true");
    }

    #[test]
    fn round_trips_through_json() {
        let v = Value::Map(Params::from_iter([(
            "vlans".to_string(),
            vec![Value::Int(10), Value::Int(20)].into_value(),
        )]));
        let json = serde_json::to_string(&v).unwrap();
        let back: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }
}

impl Value {
    /// Convert to serde_json for JSON-RPC and Lua bridge boundaries.
    /// Deliberately *not* the serde derive representation: plugins and the
    /// daemon wire speak plain JSON objects, not Rust enum tagging.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Value::Null => serde_json::Value::Null,
            Value::Bool(b) => serde_json::Value::Bool(*b),
            Value::Int(i) => serde_json::Value::from(*i),
            Value::Float(x) => serde_json::Number::from_f64(*x)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null),
            Value::Str(s) => serde_json::Value::String(s.clone()),
            Value::List(l) => serde_json::Value::Array(l.iter().map(Value::to_json).collect()),
            Value::Map(m) => {
                let mut o = serde_json::Map::new();
                for (k, v) in m {
                    o.insert(k.clone(), v.to_json());
                }
                serde_json::Value::Object(o)
            }
        }
    }

    pub fn from_json(v: &serde_json::Value) -> Value {
        match v {
            serde_json::Value::Null => Value::Null,
            serde_json::Value::Bool(b) => Value::Bool(*b),
            serde_json::Value::Number(n) => match n.as_i64() {
                Some(i) => Value::Int(i),
                None => Value::Float(n.as_f64().unwrap_or(0.0)),
            },
            serde_json::Value::String(s) => Value::Str(s.clone()),
            serde_json::Value::Array(a) => Value::List(a.iter().map(Value::from_json).collect()),
            serde_json::Value::Object(o) => {
                let mut m = Params::new();
                for (k, v) in o {
                    m.insert(k.clone(), Value::from_json(v));
                }
                Value::Map(m)
            }
        }
    }
}

#[cfg(test)]
mod json_tests {
    use super::*;

    #[test]
    fn json_bridge_is_plain_not_tagged() {
        let v = Value::Map(Params::from_iter([
            ("name".to_owned(), Value::Str("LAB".into())),
            ("id".to_owned(), Value::Int(35)),
        ]));
        let j = v.to_json();
        assert_eq!(j["name"], serde_json::json!("LAB"));
        assert_eq!(Value::from_json(&j), v);
    }
}
