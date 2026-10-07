//! Value-free structural nodes. Checked syntax and limits do not authorize names.

use std::fmt;
mod admission;
pub use admission::{AdmissionError, AdmissionInputs, SourceAssignment, validate_admission};
mod batch;
pub use batch::{AuthorityRequest, Batch, BatchError};
mod extract;
mod policy;
mod scalar;
pub use policy::{PolicyError, PolicyKeys, VerifiedPolicy};
pub use scalar::{ScalarError, Timestamp, UnsignedInteger};
mod wire;
pub use extract::{Completeness, ExtractionPolicy, Observation, ObservationReason, extract_json};

pub const MAX_NAME_SCALARS: usize = 64;
pub const MAX_FIELDS: usize = 256;
pub const MAX_DEPTH: usize = 32;
pub const MAX_ALTERNATIVES: usize = 64;
pub const MAX_CANONICAL_BYTES: usize = 65_536;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Binary,
    Object,
    Array,
    Union,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnknownReason {
    Empty,
    Unsupported,
    Limit,
    Malformed,
    Encrypted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    NonPrimitiveKind,
    EmptyName,
    NameTooLong,
    TooManyFields,
    DuplicateField,
    TooDeep,
    EmptyUnion,
    TooManyAlternatives,
    CanonicalTooLarge,
    WireTooLarge,
    InvalidWireJson,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    Primitive(Kind),
    Unknown(UnknownReason),
    Object(Vec<(String, Shape)>, Option<Box<Shape>>),
    Array(Box<Shape>),
    Union(Vec<Shape>),
}

/// A normalized tree with no public unchecked representation or observed values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Shape {
    node: Node,
    depth: usize,
}

impl Shape {
    pub fn primitive(kind: Kind) -> Result<Self, Error> {
        match kind {
            Kind::Null
            | Kind::Boolean
            | Kind::Integer
            | Kind::Number
            | Kind::String
            | Kind::Binary => Self::checked(Node::Primitive(kind), 1),
            _ => Err(Error::NonPrimitiveKind),
        }
    }

    pub fn unknown(reason: UnknownReason) -> Self {
        Self {
            node: Node::Unknown(reason),
            depth: 1,
        }
    }

    /// Names must already be policy-approved. Unicode is preserved without normalization.
    pub fn object(
        mut fields: Vec<(String, Shape)>,
        additional: Option<Shape>,
    ) -> Result<Self, Error> {
        if fields.len() > MAX_FIELDS {
            return Err(Error::TooManyFields);
        }
        if fields.iter().any(|(name, _)| name.is_empty()) {
            return Err(Error::EmptyName);
        }
        if fields
            .iter()
            .any(|(name, _)| name.chars().take(MAX_NAME_SCALARS + 1).count() > MAX_NAME_SCALARS)
        {
            return Err(Error::NameTooLong);
        }
        fields.sort_unstable_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
        if fields.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(Error::DuplicateField);
        }
        let depth = fields
            .iter()
            .map(|(_, child)| child.depth)
            .chain(additional.iter().map(|child| child.depth))
            .max()
            .unwrap_or(0)
            + 1;
        Self::checked(Node::Object(fields, additional.map(Box::new)), depth)
    }

    pub fn array(items: Self) -> Result<Self, Error> {
        let depth = items.depth + 1;
        Self::checked(Node::Array(Box::new(items)), depth)
    }

    pub fn empty_array() -> Result<Self, Error> {
        Self::array(Self::unknown(UnknownReason::Empty))
    }

    pub fn union(alternatives: Vec<Self>) -> Result<Self, Error> {
        if alternatives.len() > MAX_ALTERNATIVES {
            return Err(Error::TooManyAlternatives);
        }
        let mut unique = Vec::new();
        for alternative in alternatives {
            match alternative.node {
                Node::Union(children) => {
                    for child in children {
                        Self::add_unique(&mut unique, child)?;
                    }
                }
                _ => Self::add_unique(&mut unique, alternative)?,
            }
        }
        if unique.is_empty() {
            return Err(Error::EmptyUnion);
        }
        if unique.len() == 1 {
            return Ok(unique.remove(0));
        }
        // All unique sort keys together are bounded, not merely each individual key.
        let mut keyed = Vec::with_capacity(unique.len());
        let mut remaining = MAX_CANONICAL_BYTES;
        for shape in unique {
            let mut writer = Writer::new(remaining);
            shape.encode(&mut writer)?;
            remaining -= writer.bytes.len();
            keyed.push((writer.bytes, shape));
        }
        keyed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let depth = keyed.iter().map(|(_, shape)| shape.depth).max().unwrap() + 1;
        Self::checked(
            Node::Union(keyed.into_iter().map(|(_, shape)| shape).collect()),
            depth,
        )
    }

    fn add_unique(unique: &mut Vec<Self>, shape: Self) -> Result<(), Error> {
        if !unique.contains(&shape) {
            if unique.len() == MAX_ALTERNATIVES {
                return Err(Error::TooManyAlternatives);
            }
            unique.push(shape);
        }
        Ok(())
    }

    pub fn kind(&self) -> Kind {
        match &self.node {
            Node::Primitive(kind) => *kind,
            Node::Unknown(_) => Kind::Unknown,
            Node::Object(..) => Kind::Object,
            Node::Array(_) => Kind::Array,
            Node::Union(_) => Kind::Union,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::new(MAX_CANONICAL_BYTES);
        self.encode(&mut writer)?;
        Ok(writer.bytes)
    }

    fn checked(node: Node, depth: usize) -> Result<Self, Error> {
        if depth > MAX_DEPTH {
            return Err(Error::TooDeep);
        }
        let shape = Self { node, depth };
        shape.canonical_bytes()?;
        Ok(shape)
    }

    fn encode(&self, out: &mut Writer) -> Result<(), Error> {
        out.push(b"[")?;
        out.string(match self.kind() {
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
        })?;
        match &self.node {
            Node::Primitive(_) => {}
            Node::Unknown(reason) => {
                out.push(b",")?;
                out.string(match reason {
                    UnknownReason::Empty => "empty",
                    UnknownReason::Unsupported => "unsupported",
                    UnknownReason::Limit => "limit",
                    UnknownReason::Malformed => "malformed",
                    UnknownReason::Encrypted => "encrypted",
                })?;
            }
            Node::Array(items) => {
                out.push(b",")?;
                items.encode(out)?;
            }
            Node::Object(fields, additional) => {
                out.push(b",[")?;
                for (index, (name, child)) in fields.iter().enumerate() {
                    if index != 0 {
                        out.push(b",")?;
                    }
                    out.push(b"[")?;
                    out.string(name)?;
                    out.push(b",")?;
                    child.encode(out)?;
                    out.push(b"]")?;
                }
                out.push(b"],")?;
                match additional {
                    Some(child) => child.encode(out)?,
                    None => out.push(b"null")?,
                }
            }
            Node::Union(children) => {
                out.push(b",[")?;
                for (index, child) in children.iter().enumerate() {
                    if index != 0 {
                        out.push(b",")?;
                    }
                    child.encode(out)?;
                }
                out.push(b"]")?;
            }
        }
        out.push(b"]")
    }
}

struct Writer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Writer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(Error::CanonicalTooLarge);
        }
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn string(&mut self, value: &str) -> Result<(), Error> {
        const HEX: &[u8] = b"0123456789abcdef";
        self.push(b"\"")?;
        for byte in value.as_bytes() {
            match *byte {
                b'"' => self.push(b"\\\"")?,
                b'\\' => self.push(b"\\\\")?,
                0..=31 => self.push(&[
                    b'\\',
                    b'u',
                    b'0',
                    b'0',
                    HEX[(byte >> 4) as usize],
                    HEX[(byte & 15) as usize],
                ])?,
                _ => self.push(&[*byte])?,
            }
        }
        self.push(b"\"")
    }
}
