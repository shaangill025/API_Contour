use crate::{
    Error, Kind, MAX_ALTERNATIVES, MAX_CANONICAL_BYTES, MAX_DEPTH, MAX_FIELDS, MAX_NAME_SCALARS,
    Node, Shape, UnknownReason,
};
use serde::Serialize;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::ser::{SerializeMap, Serializer};
use sha2::{Digest, Sha256};
use std::{fmt, io};

fn invalid<E: de::Error>() -> E {
    E::custom("invalid structure")
}

impl Shape {
    /// Decode structure-only wire JSON. This does not approve submitted field names.
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_CANONICAL_BYTES {
            return Err(Error::WireTooLarge);
        }
        let mut decoder = serde_json::Deserializer::from_slice(bytes);
        let shape = Seed(1)
            .deserialize(&mut decoder)
            .map_err(|_| Error::InvalidWireJson)?;
        decoder.end().map_err(|_| Error::InvalidWireJson)?;
        Ok(shape)
    }

    /// Emit normalized wire JSON, bounded separately from canonical bytes.
    pub fn to_wire_json(&self) -> Result<Vec<u8>, Error> {
        let mut output = WireWriter(Vec::new());
        serde_json::to_writer(&mut output, self).map_err(|_| Error::WireTooLarge)?;
        Ok(output.0)
    }

    /// SHA-256 of the versioned domain followed by canonical bytes, in lowercase hex.
    pub fn fingerprint(&self) -> Result<String, Error> {
        let mut digest = Sha256::new();
        digest.update(b"apicontour/structure/1\n");
        digest.update(self.canonical_bytes()?);
        let mut output = String::with_capacity(64);
        const HEX: &[u8] = b"0123456789abcdef";
        for byte in digest.finalize() {
            output.push(char::from(HEX[(byte >> 4) as usize]));
            output.push(char::from(HEX[(byte & 15) as usize]));
        }
        Ok(output)
    }
}

struct Seed(usize);
impl<'de> DeserializeSeed<'de> for Seed {
    type Value = Shape;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Shape, D::Error> {
        if self.0 > MAX_DEPTH {
            return Err(invalid());
        }
        decoder.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for Seed {
    type Value = Shape;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("structure object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Shape, M::Error> {
        let (mut kind, mut reason, mut fields, mut additional, mut items, mut alternatives) =
            (None, None, None, None, None, None);
        let mut seen = 0u8;
        while let Some(key) = map.next_key::<String>()? {
            let bit = match key.as_str() {
                "kind" => 1,
                "reason" => 2,
                "fields" => 4,
                "additional" => 8,
                "items" => 16,
                "alternatives" => 32,
                _ => return Err(invalid()),
            };
            if seen & bit != 0 {
                return Err(invalid());
            }
            seen |= bit;
            match bit {
                1 => kind = Some(map.next_value::<String>()?),
                2 => reason = Some(map.next_value::<String>()?),
                4 => fields = Some(map.next_value_seed(Fields(self.0 + 1))?),
                8 => additional = Some(map.next_value_seed(Optional(self.0 + 1))?),
                16 => items = Some(map.next_value_seed(Seed(self.0 + 1))?),
                32 => alternatives = Some(map.next_value_seed(Alternatives(self.0 + 1))?),
                _ => unreachable!(),
            }
        }
        let shape = match (kind.as_deref(), seen) {
            (Some("null"), 1) => Shape::primitive(Kind::Null),
            (Some("boolean"), 1) => Shape::primitive(Kind::Boolean),
            (Some("integer"), 1) => Shape::primitive(Kind::Integer),
            (Some("number"), 1) => Shape::primitive(Kind::Number),
            (Some("string"), 1) => Shape::primitive(Kind::String),
            (Some("binary"), 1) => Shape::primitive(Kind::Binary),
            (Some("unknown"), 3) => Ok(Shape::unknown(match reason.as_deref() {
                Some("empty") => UnknownReason::Empty,
                Some("unsupported") => UnknownReason::Unsupported,
                Some("limit") => UnknownReason::Limit,
                Some("malformed") => UnknownReason::Malformed,
                Some("encrypted") => UnknownReason::Encrypted,
                _ => return Err(invalid()),
            })),
            (Some("object"), 13) => {
                Shape::object(fields.ok_or_else(invalid)?, additional.ok_or_else(invalid)?)
            }
            (Some("array"), 17) => Shape::array(items.ok_or_else(invalid)?),
            (Some("union"), 33) => Shape::union(alternatives.ok_or_else(invalid)?),
            _ => return Err(invalid()),
        };
        shape.map_err(|_| invalid())
    }
}

struct Fields(usize);
impl<'de> DeserializeSeed<'de> for Fields {
    type Value = Vec<(String, Shape)>;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_map(self)
    }
}
impl<'de> Visitor<'de> for Fields {
    type Value = Vec<(String, Shape)>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("fields object")
    }
    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut fields: Vec<(String, Shape)> = Vec::new();
        while let Some(name) = map.next_key::<String>()? {
            if fields.len() == MAX_FIELDS
                || name.is_empty()
                || name.chars().take(MAX_NAME_SCALARS + 1).count() > MAX_NAME_SCALARS
                || fields.iter().any(|(existing, _)| existing == &name)
            {
                return Err(invalid());
            }
            fields.push((name, map.next_value_seed(Seed(self.0))?));
        }
        Ok(fields)
    }
}

struct Optional(usize);
impl<'de> DeserializeSeed<'de> for Optional {
    type Value = Option<Shape>;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_option(self)
    }
}
impl<'de> Visitor<'de> for Optional {
    type Value = Option<Shape>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("structure or null")
    }
    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }
    fn visit_some<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        Seed(self.0).deserialize(decoder).map(Some)
    }
}

struct Alternatives(usize);
impl<'de> DeserializeSeed<'de> for Alternatives {
    type Value = Vec<Shape>;
    fn deserialize<D: de::Deserializer<'de>>(self, decoder: D) -> Result<Self::Value, D::Error> {
        decoder.deserialize_seq(self)
    }
}
impl<'de> Visitor<'de> for Alternatives {
    type Value = Vec<Shape>;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unique alternatives")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut sequence: S) -> Result<Self::Value, S::Error> {
        let mut alternatives = Vec::new();
        while let Some(shape) = sequence.next_element_seed(Seed(self.0))? {
            if alternatives.len() == MAX_ALTERNATIVES
                || shape.kind() == Kind::Union
                || alternatives.contains(&shape)
            {
                return Err(invalid());
            }
            alternatives.push(shape);
        }
        if alternatives.len() < 2 {
            return Err(invalid());
        }
        Ok(alternatives)
    }
}

fn kind_name(kind: Kind) -> &'static str {
    match kind {
        Kind::Null => "null",
        Kind::Boolean => "boolean",
        Kind::Integer => "integer",
        Kind::Number => "number",
        Kind::String => "string",
        Kind::Binary => "binary",
        Kind::Object => "object",
        Kind::Array => "array",
        Kind::Union => "union",
        Kind::Unknown => "unknown",
    }
}

impl Serialize for Shape {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("kind", kind_name(self.kind()))?;
        match &self.node {
            Node::Primitive(_) => {}
            Node::Unknown(reason) => map.serialize_entry(
                "reason",
                match reason {
                    UnknownReason::Empty => "empty",
                    UnknownReason::Unsupported => "unsupported",
                    UnknownReason::Limit => "limit",
                    UnknownReason::Malformed => "malformed",
                    UnknownReason::Encrypted => "encrypted",
                },
            )?,
            Node::Object(fields, additional) => {
                map.serialize_entry("fields", &FieldMap(fields))?;
                map.serialize_entry("additional", additional)?;
            }
            Node::Array(items) => map.serialize_entry("items", items)?,
            Node::Union(alternatives) => map.serialize_entry("alternatives", alternatives)?,
        }
        map.end()
    }
}

struct FieldMap<'a>(&'a [(String, Shape)]);
impl Serialize for FieldMap<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, shape) in self.0 {
            map.serialize_entry(name, shape)?;
        }
        map.end()
    }
}

struct WireWriter(Vec<u8>);
impl io::Write for WireWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_CANONICAL_BYTES - self.0.len() {
            return Err(io::Error::other("structure too large"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
