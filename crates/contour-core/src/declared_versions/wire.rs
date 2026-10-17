//! Internal representation validation; input-graph binding belongs to persistence.
use super::*;
use crate::{UnsignedInteger, batch::Bounded};
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
    ser::{SerializeMap, SerializeSeq},
};
use std::io;

pub const MAX_DECLARED_COMPARISON_BYTES: usize = 1_048_576;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredComparisonCodecError {
    Wire,
    Version,
    Size,
    Limit,
    Invariant,
}
impl fmt::Display for DeclaredComparisonCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeclaredComparisonCodecError {}
type Error = DeclaredComparisonCodecError;
macro_rules! enum_wire {
    ($ty:ident, $($variant:ident => $name:literal),+ $(,)?) => {
        impl Serialize for $ty {
            fn serialize<S:Serializer>(&self,s:S)->Result<S::Ok,S::Error> {
                s.serialize_str(match self {$(Self::$variant=>$name),+})
            }
        }
        impl<'de> Deserialize<'de> for $ty {
            fn deserialize<D:Deserializer<'de>>(d:D)->Result<Self,D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value=$ty;
                    fn expecting(&self,f:&mut fmt::Formatter<'_>)->fmt::Result {f.write_str("closed comparison enum")}
                    fn visit_str<E:de::Error>(self,s:&str)->Result<Self::Value,E> {
                        match s {$($name=>Ok($ty::$variant),)+ _=>Err(E::custom("comparison enum"))}
                    }
                }
                d.deserialize_str(V)
            }
        }
    }
}
enum_wire!(DeclaredCompatibility, Compatible=>"compatible",Incompatible=>"incompatible",Inconclusive=>"inconclusive");
enum_wire!(DeclaredVersionDifferenceKind, TypeChanged=>"type_changed",NullMembershipChanged=>"null_membership_changed",RequirednessChanged=>"requiredness_changed",FieldAdded=>"field_added",FieldRemoved=>"field_removed",AdditionalPolicyChanged=>"additional_policy_changed",InsufficientEvidence=>"insufficient_evidence");
enum_wire!(DeclaredAdditionalPolicy, Allowed=>"allowed",Forbidden=>"forbidden",Schema=>"schema");
#[derive(Clone, Copy)]
enum Label {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Binary,
    Object,
    Array,
    Unknown,
}
enum_wire!(Label,Null=>"null",Boolean=>"boolean",Integer=>"integer",Number=>"number",String=>"string",Binary=>"binary",Object=>"object",Array=>"array",Unknown=>"unknown");
impl Label {
    fn kind(self) -> Kind {
        match self {
            Self::Null => Kind::Null,
            Self::Boolean => Kind::Boolean,
            Self::Integer => Kind::Integer,
            Self::Number => Kind::Number,
            Self::String => Kind::String,
            Self::Binary => Kind::Binary,
            Self::Object => Kind::Object,
            Self::Array => Kind::Array,
            Self::Unknown => Kind::Unknown,
        }
    }
    fn checked(kind: Kind) -> Result<Self, Error> {
        Ok(match kind {
            Kind::Null => Self::Null,
            Kind::Boolean => Self::Boolean,
            Kind::Integer => Self::Integer,
            Kind::Number => Self::Number,
            Kind::String => Self::String,
            Kind::Binary => Self::Binary,
            Kind::Object => Self::Object,
            Kind::Array => Self::Array,
            Kind::Unknown => Self::Unknown,
            Kind::Union => return Err(Error::Invariant),
        })
    }
}
#[derive(Serialize)]
#[serde(transparent)]
struct Path(String);
impl<'de> Deserialize<'de> for Path {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Path;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded comparison path")
            }
            fn visit_str<E: de::Error>(self, s: &str) -> Result<Path, E> {
                if s.is_empty()
                    || s.chars().take(MAX_COMPARISON_PATH_SCALARS + 1).count()
                        > MAX_COMPARISON_PATH_SCALARS
                {
                    return Err(E::custom("path limit"));
                }
                Ok(Path(s.to_owned()))
            }
        }
        d.deserialize_str(V)
    }
}
fn required_nullable<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(d)
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Difference {
    path: Path,
    kind: DeclaredVersionDifferenceKind,
    #[serde(deserialize_with = "required_nullable")]
    baseline_kind: Option<Label>,
    #[serde(deserialize_with = "required_nullable")]
    candidate_kind: Option<Label>,
    #[serde(deserialize_with = "required_nullable")]
    baseline_required: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    candidate_required: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    baseline_includes_null: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    candidate_includes_null: Option<bool>,
    #[serde(deserialize_with = "required_nullable")]
    baseline_additional: Option<DeclaredAdditionalPolicy>,
    #[serde(deserialize_with = "required_nullable")]
    candidate_additional: Option<DeclaredAdditionalPolicy>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: UnsignedInteger,
    compatibility: DeclaredCompatibility,
    differences: Bounded<Difference, MAX_COMPARISON_DIFFERENCES>,
}
impl Difference {
    fn checked(d: &DeclaredVersionDifference) -> Result<Self, Error> {
        Ok(Self {
            path: Path(d.path.clone()),
            kind: d.kind,
            baseline_kind: d.baseline_kind.map(Label::checked).transpose()?,
            candidate_kind: d.candidate_kind.map(Label::checked).transpose()?,
            baseline_required: d.baseline_required,
            candidate_required: d.candidate_required,
            baseline_includes_null: d.baseline_includes_null,
            candidate_includes_null: d.candidate_includes_null,
            baseline_additional: d.baseline_additional,
            candidate_additional: d.candidate_additional,
        })
    }
    fn into_checked(self) -> DeclaredVersionDifference {
        DeclaredVersionDifference {
            path: self.path.0,
            kind: self.kind,
            baseline_kind: self.baseline_kind.map(Label::kind),
            candidate_kind: self.candidate_kind.map(Label::kind),
            baseline_required: self.baseline_required,
            candidate_required: self.candidate_required,
            baseline_includes_null: self.baseline_includes_null,
            candidate_includes_null: self.candidate_includes_null,
            baseline_additional: self.baseline_additional,
            candidate_additional: self.candidate_additional,
        }
    }
}
#[derive(PartialEq)]
enum Location {
    Root,
    Field,
    Items,
    Additional,
}
fn location(path: &str) -> Result<Location, Error> {
    let mut segments = path.split('/');
    if segments.next() != Some("#") {
        return Err(Error::Invariant);
    }
    let mut location = Location::Root;
    while let Some(segment) = segments.next() {
        location = match segment {
            "items" => Location::Items,
            "additional" => Location::Additional,
            "fields" => {
                let name = segments.next().ok_or(Error::Invariant)?;
                if name.is_empty() {
                    return Err(Error::Invariant);
                }
                let mut chars = name.chars();
                let mut count = 0;
                while let Some(c) = chars.next() {
                    if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                        return Err(Error::Invariant);
                    }
                    count += 1;
                }
                if count > crate::MAX_NAME_SCALARS {
                    return Err(Error::Invariant);
                }
                Location::Field
            }
            _ => return Err(Error::Invariant),
        };
    }
    Ok(location)
}
fn validate(value: &DeclaredVersionComparison) -> Result<(), Error> {
    if value.differences.len() > MAX_COMPARISON_DIFFERENCES {
        return Err(Error::Limit);
    }
    let mut bytes = 0;
    let mut unknowns = 0;
    let mut previous: Option<&str> = None;
    let mut kinds = 0u8;
    for d in &value.differences {
        if d.path.chars().count() > MAX_COMPARISON_PATH_SCALARS
            || d.path.len() > MAX_COMPARISON_PATH_BYTES - bytes
        {
            return Err(Error::Limit);
        }
        bytes += d.path.len();
        if previous.is_some_and(|p| p.as_bytes() > d.path.as_bytes()) {
            return Err(Error::Invariant);
        }
        if previous != Some(d.path.as_str()) {
            kinds = 0;
        }
        let bit = 1u8 << (d.kind as u8);
        if kinds & bit != 0 {
            return Err(Error::Invariant);
        }
        kinds |= bit;
        previous = Some(&d.path);
        let at = location(&d.path)?;
        if [d.baseline_kind, d.candidate_kind].contains(&Some(Kind::Union)) {
            return Err(Error::Invariant);
        }
        let labels = d.baseline_kind.is_some() && d.candidate_kind.is_some();
        let known = ![d.baseline_kind, d.candidate_kind].contains(&Some(Kind::Unknown));
        let required = d.baseline_required.is_some()
            && d.candidate_required.is_some()
            && d.baseline_required != d.candidate_required;
        let nulls = d.baseline_includes_null.is_some()
            && d.candidate_includes_null.is_some()
            && d.baseline_includes_null != d.candidate_includes_null;
        let no_required = d.baseline_required.is_none() && d.candidate_required.is_none();
        let no_nulls = d.baseline_includes_null.is_none() && d.candidate_includes_null.is_none();
        let no_additional = d.baseline_additional.is_none() && d.candidate_additional.is_none();
        use DeclaredVersionDifferenceKind as D;
        let valid = match d.kind {
            D::TypeChanged => {
                labels
                    && known
                    && d.baseline_kind != d.candidate_kind
                    && no_required
                    && no_nulls
                    && no_additional
            }
            D::NullMembershipChanged => {
                labels
                    && known
                    && nulls
                    && no_required
                    && no_additional
                    && (d.baseline_kind != Some(Kind::Null)
                        || d.baseline_includes_null == Some(true))
                    && (d.candidate_kind != Some(Kind::Null)
                        || d.candidate_includes_null == Some(true))
            }
            D::RequirednessChanged => {
                at == Location::Field && labels && required && no_nulls && no_additional
            }
            D::FieldAdded => {
                at == Location::Field
                    && d.baseline_kind.is_none()
                    && d.baseline_required.is_none()
                    && d.candidate_kind.is_some()
                    && d.candidate_required.is_some()
                    && no_nulls
                    && no_additional
            }
            D::FieldRemoved => {
                at == Location::Field
                    && d.candidate_kind.is_none()
                    && d.candidate_required.is_none()
                    && d.baseline_kind.is_some()
                    && d.baseline_required.is_some()
                    && no_nulls
                    && no_additional
            }
            D::AdditionalPolicyChanged => {
                at == Location::Additional
                    && no_required
                    && no_nulls
                    && d.baseline_additional.is_some()
                    && d.candidate_additional.is_some()
                    && d.baseline_additional != d.candidate_additional
                    && d.baseline_kind.is_some()
                        == (d.baseline_additional == Some(DeclaredAdditionalPolicy::Schema))
                    && d.candidate_kind.is_some()
                        == (d.candidate_additional == Some(DeclaredAdditionalPolicy::Schema))
            }
            D::InsufficientEvidence => {
                unknowns += 1;
                at == Location::Root && labels && no_required && no_nulls && no_additional
            }
        };
        if !valid {
            return Err(Error::Invariant);
        }
    }
    if unknowns != usize::from(value.compatibility == DeclaredCompatibility::Inconclusive) {
        return Err(Error::Invariant);
    }
    Ok(())
}
impl DeclaredVersionComparison {
    pub fn from_wire_json(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_DECLARED_COMPARISON_BYTES {
            return Err(Error::Size);
        }
        let doc: Document = serde_json::from_slice(bytes).map_err(|_| Error::Wire)?;
        if doc.version.get() != 1 {
            return Err(Error::Version);
        }
        let value = Self {
            compatibility: doc.compatibility,
            differences: doc
                .differences
                .0
                .into_iter()
                .map(Difference::into_checked)
                .collect(),
        };
        validate(&value)?;
        value.to_wire_json()?;
        Ok(value)
    }
    pub fn to_wire_json(&self) -> Result<Vec<u8>, Error> {
        validate(self)?;
        let mut output = Output(Vec::new());
        serde_json::to_writer(&mut output, &Encoded(self)).map_err(|_| Error::Size)?;
        Ok(output.0)
    }
}
struct Output(Vec<u8>);
impl io::Write for Output {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > MAX_DECLARED_COMPARISON_BYTES.saturating_sub(self.0.len()) {
            return Err(io::ErrorKind::OutOfMemory.into());
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Encoded<'a>(&'a DeclaredVersionComparison);
struct Findings<'a>(&'a [DeclaredVersionDifference]);
impl Serialize for Encoded<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(Some(3))?;
        map.serialize_entry("version", &1)?;
        map.serialize_entry("compatibility", &self.0.compatibility)?;
        map.serialize_entry("differences", &Findings(&self.0.differences))?;
        map.end()
    }
}
impl Serialize for Findings<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(self.0.len()))?;
        for finding in self.0 {
            seq.serialize_element(
                &Difference::checked(finding).map_err(serde::ser::Error::custom)?,
            )?;
        }
        seq.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn finding(path: String) -> DeclaredVersionDifference {
        DeclaredVersionDifference {
            path,
            kind: DeclaredVersionDifferenceKind::TypeChanged,
            baseline_kind: Some(Kind::Integer),
            candidate_kind: Some(Kind::Number),
            baseline_required: None,
            candidate_required: None,
            baseline_includes_null: None,
            candidate_includes_null: None,
            baseline_additional: None,
            candidate_additional: None,
        }
    }
    fn result(paths: impl Iterator<Item = String>) -> DeclaredVersionComparison {
        DeclaredVersionComparison {
            compatibility: DeclaredCompatibility::Compatible,
            differences: paths.map(finding).collect(),
        }
    }
    #[test]
    fn structural_limits_are_independent_of_wire_size() {
        let mut value = result((0..10_000).map(|i| format!("#/fields/{i:06}")));
        assert_eq!(validate(&value), Ok(()));
        assert_eq!(value.to_wire_json(), Err(Error::Size));
        value.differences.push(finding("#/fields/010000".into()));
        assert_eq!(validate(&value), Err(Error::Limit));
        let mut paths = result((0..1024).map(|i| {
            format!(
                "#{}{}{}{i:04}",
                "/items".repeat(159),
                "/fields/",
                "x".repeat(57)
            )
        }));
        assert!(paths.differences.iter().all(|d| d.path.len() == 1024));
        assert_eq!(validate(&paths), Ok(()));
        paths.differences.push(finding(format!(
            "#{}{}{}1024",
            "/items".repeat(159),
            "/fields/",
            "x".repeat(57)
        )));
        assert_eq!(validate(&paths), Err(Error::Limit));
    }
    #[test]
    fn output_exact_boundary_and_one_byte_over() {
        let empty = result(std::iter::empty()).to_wire_json().unwrap().len();
        let one = result(std::iter::once("#/fields/000000".into()))
            .to_wire_json()
            .unwrap()
            .len();
        let increment = one - empty + 1;
        let count = (MAX_DECLARED_COMPARISON_BYTES - empty + 1) / increment;
        let mut value = result((0..count).map(|i| format!("#/fields/{i:06}")));
        let gap = MAX_DECLARED_COMPARISON_BYTES - value.to_wire_json().unwrap().len();
        let last = value.differences.last_mut().unwrap();
        last.path = format!(
            "#/fields/{}{}",
            "z".repeat(6 + gap % 6),
            "/items".repeat(gap / 6)
        );
        assert_eq!(
            value.to_wire_json().unwrap().len(),
            MAX_DECLARED_COMPARISON_BYTES
        );
        value.differences.last_mut().unwrap().path.insert(9, 'z');
        assert_eq!(validate(&value), Ok(()));
        assert_eq!(value.to_wire_json(), Err(Error::Size));
    }
    #[test]
    fn escaping_can_exhaust_output_before_structural_limits() {
        let value = result((0..2000).map(|i| format!("#/fields/{}{i:04}", "\0".repeat(60))));
        assert_eq!(validate(&value), Ok(()));
        assert_eq!(value.to_wire_json(), Err(Error::Size));
    }
}
