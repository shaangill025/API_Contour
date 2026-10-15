//! Versioned flat codec, bounded before parse and while collecting nodes/edges.
use crate::{MAX_OPERATION_BYTES, UnsignedInteger, batch::Bounded, declared::*};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, MapAccess, SeqAccess, Visitor},
    ser::SerializeMap,
};
use serde_json::value::RawValue;
use std::{fmt, io};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document<'a> {
    version: UnsignedInteger,
    #[serde(borrow)]
    operation: &'a RawValue,
    root: u32,
    nodes: Nodes,
    definitions: Bounded<Definition, 256>,
    omissions: Bounded<Omission, 2>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Definition {
    name: Name,
    target: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Property {
    name: Name,
    required: bool,
    target: u32,
}
struct Name(String);
impl<'de> Deserialize<'de> for Name {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct NameVisitor;
        impl Visitor<'_> for NameVisitor {
            type Value = Name;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded local name")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Name, E> {
                if value.is_empty() || value.chars().take(65).count() > 64 {
                    return Err(E::custom("name bound"));
                }
                Ok(Name(value.to_owned()))
            }
        }
        decoder.deserialize_str(NameVisitor)
    }
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Tag {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Binary,
    Object,
    Array,
    Union,
    Reference,
    Unknown,
}
impl<'de> Deserialize<'de> for DeclaredAdditional {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Additional;
        impl<'de> Visitor<'de> for Additional {
            type Value = DeclaredAdditional;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("additional properties policy")
            }
            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                match value {
                    "allowed" => Ok(DeclaredAdditional::Allowed),
                    "forbidden" => Ok(DeclaredAdditional::Forbidden),
                    _ => Err(E::custom("additional tag")),
                }
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                if map.next_key::<String>()?.as_deref() != Some("schema") {
                    return Err(de::Error::custom("additional schema"));
                }
                let target = map.next_value()?;
                if map.next_key::<String>()?.is_some() {
                    return Err(de::Error::custom("additional field"));
                }
                Ok(DeclaredAdditional::Schema(target))
            }
        }
        decoder.deserialize_any(Additional)
    }
}
struct WireNode(DeclaredNode);
impl<'de> Deserialize<'de> for WireNode {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct NodeVisitor;
        impl<'de> Visitor<'de> for NodeVisitor {
            type Value = WireNode;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("declared node")
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
                let (
                    mut id,
                    mut tag,
                    mut omissions,
                    mut properties,
                    mut additional,
                    mut items,
                    mut alternatives,
                    mut reference,
                    mut reason,
                ) = (None, None, None, None, None, None, None, None, None);
                let mut seen = 0u16;
                while let Some(key) = map.next_key::<String>()? {
                    let bit = match key.as_str() {
                        "id" => 1,
                        "kind" => 2,
                        "omissions" => 4,
                        "properties" => 8,
                        "additional" => 16,
                        "items" => 32,
                        "alternatives" => 64,
                        "reference" => 128,
                        "reason" => 256,
                        _ => return Err(de::Error::custom("unknown node field")),
                    };
                    if seen & bit != 0 {
                        return Err(de::Error::custom("duplicate node field"));
                    }
                    seen |= bit;
                    match bit {
                        1 => id = Some(map.next_value::<u32>()?),
                        2 => tag = Some(map.next_value::<Tag>()?),
                        4 => omissions = Some(map.next_value::<Bounded<Omission, 2>>()?),
                        8 => properties = Some(map.next_value::<Bounded<Property, 256>>()?),
                        16 => additional = Some(map.next_value::<DeclaredAdditional>()?),
                        32 => items = Some(map.next_value::<u32>()?),
                        64 => alternatives = Some(map.next_value::<Bounded<u32, 64>>()?),
                        128 => reference = Some(map.next_value::<Name>()?),
                        256 => reason = Some(map.next_value::<DeclaredUnknown>()?),
                        _ => unreachable!(),
                    }
                }
                let bad = || de::Error::custom("node fields");
                let kind = match (tag.ok_or_else(bad)?, seen) {
                    (Tag::Null, 7) => DeclaredKind::Null,
                    (Tag::Boolean, 7) => DeclaredKind::Boolean,
                    (Tag::Integer, 7) => DeclaredKind::Integer,
                    (Tag::Number, 7) => DeclaredKind::Number,
                    (Tag::String, 7) => DeclaredKind::String,
                    (Tag::Binary, 7) => DeclaredKind::Binary,
                    (Tag::Object, 31) => DeclaredKind::Object {
                        properties: properties
                            .ok_or_else(bad)?
                            .0
                            .into_iter()
                            .map(|property| DeclaredProperty {
                                name: property.name.0,
                                required: property.required,
                                target: property.target,
                            })
                            .collect(),
                        additional: additional.ok_or_else(bad)?,
                    },
                    (Tag::Array, 39) => DeclaredKind::Array {
                        items: items.ok_or_else(bad)?,
                    },
                    (Tag::Union, 71) => DeclaredKind::Union {
                        alternatives: alternatives.ok_or_else(bad)?.0,
                    },
                    (Tag::Reference, 135) => DeclaredKind::Reference {
                        name: reference.ok_or_else(bad)?.0,
                    },
                    (Tag::Unknown, 263) => DeclaredKind::Unknown {
                        reason: reason.ok_or_else(bad)?,
                    },
                    _ => return Err(bad()),
                };
                Ok(WireNode(DeclaredNode {
                    id: id.ok_or_else(bad)?,
                    kind,
                    omissions: omissions.ok_or_else(bad)?.0,
                }))
            }
        }
        decoder.deserialize_map(NodeVisitor)
    }
}
struct Nodes(Vec<DeclaredNode>);
impl<'de> Deserialize<'de> for Nodes {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct NodeList;
        impl<'de> Visitor<'de> for NodeList {
            type Value = Nodes;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded graph")
            }
            fn visit_seq<S: SeqAccess<'de>>(
                self,
                mut sequence: S,
            ) -> Result<Self::Value, S::Error> {
                let mut nodes = Vec::new();
                let mut edges = 0;
                loop {
                    if nodes.len() == MAX_DECLARED_NODES {
                        if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                            return Err(de::Error::custom("node bound"));
                        }
                        break;
                    }
                    let Some(WireNode(node)) = sequence.next_element::<WireNode>()? else {
                        break;
                    };
                    edges += match &node.kind {
                        DeclaredKind::Object {
                            properties,
                            additional,
                        } => {
                            properties.len()
                                + usize::from(matches!(additional, DeclaredAdditional::Schema(_)))
                        }
                        DeclaredKind::Array { .. } | DeclaredKind::Reference { .. } => 1,
                        DeclaredKind::Union { alternatives } => alternatives.len(),
                        _ => 0,
                    };
                    if edges > MAX_DECLARED_EDGES {
                        return Err(de::Error::custom("edge bound"));
                    }
                    nodes.push(node);
                }
                Ok(Nodes(nodes))
            }
        }
        decoder.deserialize_seq(NodeList)
    }
}
impl DeclaredContract {
    /// Internal sanitized graph only, not an OpenAPI/JSON Schema importer.
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, DeclaredError> {
        if bytes.len() > MAX_DECLARED_BYTES {
            return Err(DeclaredError::Size);
        }
        let doc: Document<'_> =
            serde_json::from_slice(bytes).map_err(|_| DeclaredError::Invalid)?;
        if doc.version.get() != 1 {
            return Err(DeclaredError::Invalid);
        }
        if doc.operation.get().len() > MAX_OPERATION_BYTES {
            return Err(DeclaredError::Operation);
        }
        let operation =
            serde_json::from_str(doc.operation.get()).map_err(|_| DeclaredError::Operation)?;
        let value = Self {
            operation,
            root: doc.root,
            nodes: doc.nodes.0,
            definitions: doc
                .definitions
                .0
                .into_iter()
                .map(|definition| DeclaredDefinition {
                    name: definition.name.0,
                    target: definition.target,
                })
                .collect(),
            omissions: doc.omissions.0,
        }
        .checked()?;
        // Input whitespace/order may normalize; bounded output is a separate limit.
        value.to_wire_json()?;
        Ok(value)
    }
    /// Deterministic bytes for this graph's IDs; not graph-isomorphism canonicalization.
    pub fn to_wire_json(&self) -> Result<Vec<u8>, DeclaredError> {
        let mut output = Output(Vec::new());
        serde_json::to_writer(&mut output, self).map_err(|_| DeclaredError::Size)?;
        Ok(output.0)
    }
}
struct Output(Vec<u8>);
impl io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DECLARED_BYTES.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Serialize for DeclaredContract {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(6))?;
        map.serialize_entry("version", &1)?;
        map.serialize_entry("operation", &self.operation)?;
        map.serialize_entry("root", &self.root)?;
        map.serialize_entry("nodes", &self.nodes)?;
        map.serialize_entry("definitions", &self.definitions)?;
        map.serialize_entry("omissions", &self.omissions)?;
        map.end()
    }
}
impl Serialize for DeclaredDefinition {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("target", &self.target)?;
        map.end()
    }
}
impl Serialize for DeclaredProperty {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("required", &self.required)?;
        map.serialize_entry("target", &self.target)?;
        map.end()
    }
}
impl Serialize for DeclaredAdditional {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Allowed => serializer.serialize_str("allowed"),
            Self::Forbidden => serializer.serialize_str("forbidden"),
            Self::Schema(target) => {
                let mut map = serializer.serialize_map(Some(1))?;
                map.serialize_entry("schema", target)?;
                map.end()
            }
        }
    }
}
impl Serialize for DeclaredNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("id", &self.id)?;
        let tag = match &self.kind {
            DeclaredKind::Null => "null",
            DeclaredKind::Boolean => "boolean",
            DeclaredKind::Integer => "integer",
            DeclaredKind::Number => "number",
            DeclaredKind::String => "string",
            DeclaredKind::Binary => "binary",
            DeclaredKind::Object { .. } => "object",
            DeclaredKind::Array { .. } => "array",
            DeclaredKind::Union { .. } => "union",
            DeclaredKind::Reference { .. } => "reference",
            DeclaredKind::Unknown { .. } => "unknown",
        };
        map.serialize_entry("kind", tag)?;
        map.serialize_entry("omissions", &self.omissions)?;
        match &self.kind {
            DeclaredKind::Object {
                properties,
                additional,
            } => {
                map.serialize_entry("properties", properties)?;
                map.serialize_entry("additional", additional)?;
            }
            DeclaredKind::Array { items } => map.serialize_entry("items", items)?,
            DeclaredKind::Union { alternatives } => {
                map.serialize_entry("alternatives", alternatives)?
            }
            DeclaredKind::Reference { name } => map.serialize_entry("reference", name)?,
            DeclaredKind::Unknown { reason } => map.serialize_entry("reason", reason)?,
            _ => (),
        };
        map.end()
    }
}
