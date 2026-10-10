//! Duplicate-aware bounded transient JSON. No source text is returned in errors.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

#[derive(Default)]
struct Budget {
    values: usize,
    strings: usize,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Value, D::Error> {
        if self.depth > 64 || self.budget.values == 65536 {
            return Err(de::Error::custom("input bound"));
        }
        self.budget.values += 1;
        decoder.deserialize_any(self)
    }
}
impl Seed<'_> {
    fn string<E: de::Error>(&mut self, value: &str) -> Result<String, E> {
        if value.len() > super::import::MAX_IMPORT_BYTES.saturating_sub(self.budget.strings) {
            return Err(E::custom("string bound"));
        }
        self.budget.strings += value.len();
        Ok(value.to_owned())
    }
}
impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded JSON")
    }
    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }
    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    // Numbers are never retained by this structural subset.
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_str<E: de::Error>(mut self, v: &str) -> Result<Value, E> {
        Ok(Value::String(self.string(v)?))
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Value, S::Error> {
        let mut out = Vec::new();
        while let Some(v) = seq.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            out.push(v);
        }
        Ok(Value::Array(out))
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Value, M::Error> {
        let mut out = Map::new();
        while let Some(key) = map.next_key_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            let Value::String(key) = key else {
                return Err(de::Error::custom("key"));
            };
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            out.insert(key, value);
        }
        Ok(Value::Object(out))
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<Value, super::import::ImportError> {
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Seed {
        budget: &mut Budget::default(),
        depth: 0,
    }
    .deserialize(&mut decoder)
    .map_err(|_| super::import::ImportError::Invalid)?;
    decoder
        .end()
        .map_err(|_| super::import::ImportError::Invalid)?;
    Ok(value)
}
