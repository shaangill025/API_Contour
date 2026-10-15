//! Declared constraints against observations. Absence is not a contract change.
use crate::{
    ComparisonError, DeclaredAdditional, DeclaredContract, DeclaredKind, DeclaredNode,
    DeclaredUnknown, Kind, MAX_COMPARISON_DIFFERENCES, MAX_COMPARISON_PATH_BYTES,
    MAX_COMPARISON_PATH_SCALARS, MAX_COMPARISON_VISITS, Node, ObservedCompatibility,
    OperationObservation, Shape, UnknownReason,
};
use std::{collections::BTreeSet, fmt};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredObservationKind {
    TypeMismatch,
    NullNotDeclared,
    RequiredFieldNotObserved,
    UndeclaredFieldObserved,
    InsufficientEvidence,
    UnsupportedConstruct,
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredObservationDifference {
    pub path: String,
    pub kind: DeclaredObservationKind,
    pub declared_kind: Option<Kind>,
    pub observed_kind: Option<Kind>,
    pub declared_unknown: Option<DeclaredUnknown>,
    pub observed_unknown: Option<UnknownReason>,
}
impl fmt::Debug for DeclaredObservationDifference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredObservationDifference")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredObservationComparison {
    differences: Vec<DeclaredObservationDifference>,
}
impl DeclaredObservationComparison {
    pub fn compatibility(&self) -> ObservedCompatibility {
        ObservedCompatibility::Inconclusive
    }
    pub fn differences(&self) -> &[DeclaredObservationDifference] {
        &self.differences
    }
}
impl fmt::Debug for DeclaredObservationComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredObservationComparison")
    }
}
/// Callers authorize both inputs. Full operation identity must match, including
/// environment and direction. No observed absence proves optionality or removal.
/// Errors return no partial result. Recursion follows only the checked observed
/// tree (depth at most32); declared reference chains are resolved iteratively.
pub fn compare_declared_observation(
    declared: &DeclaredContract,
    observed: &OperationObservation<'_>,
) -> Result<DeclaredObservationComparison, ComparisonError> {
    if declared.operation() != observed.key {
        return Err(ComparisonError::OperationScope);
    }
    let mut walker = Walker {
        declared,
        differences: Vec::new(),
        visits: 0,
        path_bytes: 0,
    };
    if !declared.omissions().is_empty() {
        walker.emit(
            "#",
            DeclaredObservationKind::UnsupportedConstruct,
            None,
            Some(observed.structure),
        )?;
    }
    if observed.completeness != "complete"
        || !observed.reasons.is_empty()
        || observed.sample_numerator != observed.sample_denominator
        || observed.route_uncertain
    {
        walker.emit(
            "#",
            DeclaredObservationKind::InsufficientEvidence,
            None,
            Some(observed.structure),
        )?;
    }
    walker.walk(declared.root(), observed.structure, "#")?;
    Ok(DeclaredObservationComparison {
        differences: walker.differences,
    })
}
struct Walker<'a> {
    declared: &'a DeclaredContract,
    differences: Vec<DeclaredObservationDifference>,
    visits: usize,
    path_bytes: usize,
}
impl<'a> Walker<'a> {
    fn visit(&mut self) -> Result<(), ComparisonError> {
        if self.visits == MAX_COMPARISON_VISITS {
            return Err(ComparisonError::WorkLimit);
        }
        self.visits += 1;
        Ok(())
    }
    fn emit(
        &mut self,
        path: &str,
        kind: DeclaredObservationKind,
        declared: Option<&DeclaredNode>,
        observed: Option<&Shape>,
    ) -> Result<(), ComparisonError> {
        if self.differences.len() == MAX_COMPARISON_DIFFERENCES {
            return Err(ComparisonError::DifferenceLimit);
        }
        if path.len() > MAX_COMPARISON_PATH_BYTES - self.path_bytes {
            return Err(ComparisonError::PathLimit);
        }
        self.path_bytes += path.len();
        self.differences.push(DeclaredObservationDifference {
            path: path.to_owned(),
            kind,
            declared_kind: declared.and_then(|n| node_kind(n.kind())),
            observed_kind: observed.map(Shape::kind),
            declared_unknown: declared.and_then(|n| {
                if let DeclaredKind::Unknown { reason } = n.kind() {
                    Some(*reason)
                } else {
                    None
                }
            }),
            observed_unknown: observed.and_then(unknown),
        });
        Ok(())
    }
    fn resolve(&mut self, mut id: u32) -> Result<Option<&'a DeclaredNode>, ComparisonError> {
        let mut seen = BTreeSet::new();
        loop {
            self.visit()?;
            if !seen.insert(id) {
                return Ok(None);
            }
            let node = self.declared.node(id).expect("checked declared target");
            match node.kind() {
                DeclaredKind::Reference { name } => {
                    id = self.declared.definition(name).expect("checked definition");
                }
                _ => return Ok(Some(node)),
            }
        }
    }
    fn walk(&mut self, id: u32, observed: &Shape, path: &str) -> Result<(), ComparisonError> {
        self.visit()?;
        let Some(mut declared) = self.resolve(id)? else {
            self.emit(
                path,
                DeclaredObservationKind::InsufficientEvidence,
                None,
                Some(observed),
            )?;
            return self.scan(observed, path);
        };
        if unknown(observed).is_some() || matches!(declared.kind(), DeclaredKind::Unknown { .. }) {
            self.emit(
                path,
                DeclaredObservationKind::InsufficientEvidence,
                Some(declared),
                Some(observed),
            )?;
            return if unknown(observed).is_none() {
                self.scan(observed, path)
            } else {
                Ok(())
            };
        }
        let mut declared_null = matches!(declared.kind(), DeclaredKind::Null);
        if let DeclaredKind::Union { alternatives } = declared.kind() {
            if alternatives.len() != 2 {
                self.emit(
                    path,
                    DeclaredObservationKind::UnsupportedConstruct,
                    Some(declared),
                    Some(observed),
                )?;
                return self.scan(observed, path);
            }
            let a = self.resolve(alternatives[0])?;
            let b = self.resolve(alternatives[1])?;
            declared = match (a, b) {
                (Some(a), Some(b))
                    if matches!(a.kind(), DeclaredKind::Null)
                        && !matches!(b.kind(), DeclaredKind::Null | DeclaredKind::Union { .. }) =>
                {
                    b
                }
                (Some(a), Some(b))
                    if matches!(b.kind(), DeclaredKind::Null)
                        && !matches!(a.kind(), DeclaredKind::Null | DeclaredKind::Union { .. }) =>
                {
                    a
                }
                _ => {
                    self.emit(
                        path,
                        DeclaredObservationKind::UnsupportedConstruct,
                        Some(declared),
                        Some(observed),
                    )?;
                    return self.scan(observed, path);
                }
            };
            declared_null = true;
        }
        let mut value = observed;
        if let Node::Union(alternatives) = &observed.node {
            self.visit()?;
            if alternatives.len() == 2 && alternatives.iter().any(|s| s.kind() == Kind::Null) {
                value = alternatives
                    .iter()
                    .find(|s| s.kind() != Kind::Null)
                    .expect("normalized distinct alternatives");
                if !declared_null {
                    self.emit(
                        path,
                        DeclaredObservationKind::NullNotDeclared,
                        Some(declared),
                        Some(observed),
                    )?;
                }
            } else {
                self.emit(
                    path,
                    DeclaredObservationKind::UnsupportedConstruct,
                    Some(declared),
                    Some(observed),
                )?;
                return self.scan(observed, path);
            }
        } else if observed.kind() == Kind::Null {
            return if declared_null {
                Ok(())
            } else {
                self.emit(
                    path,
                    DeclaredObservationKind::NullNotDeclared,
                    Some(declared),
                    Some(observed),
                )
            };
        }
        if unknown(value).is_some() || matches!(declared.kind(), DeclaredKind::Unknown { .. }) {
            self.emit(
                path,
                DeclaredObservationKind::InsufficientEvidence,
                Some(declared),
                Some(value),
            )?;
            return if unknown(value).is_none() {
                self.scan(value, path)
            } else {
                Ok(())
            };
        }
        match (declared.kind(), &value.node) {
            (
                DeclaredKind::Object {
                    properties,
                    additional,
                },
                Node::Object(fields, extra),
            ) => {
                let (mut di, mut oi) = (0, 0);
                while di < properties.len() || oi < fields.len() {
                    self.visit()?;
                    match (properties.get(di), fields.get(oi)) {
                        (Some(property), Some((name, shape))) if property.name() == name => {
                            self.walk(property.target(), shape, &field(path, name)?)?;
                            di += 1;
                            oi += 1;
                        }
                        (Some(property), Some((name, _)))
                            if property.name().as_bytes() < name.as_bytes() =>
                        {
                            self.absent(property, path)?;
                            di += 1;
                        }
                        (Some(property), None) => {
                            self.absent(property, path)?;
                            di += 1;
                        }
                        (_, Some((name, shape))) => {
                            self.extra(*additional, shape, &field(path, name)?, false)?;
                            oi += 1;
                        }
                        (None, None) => break,
                    }
                }
                if let Some(extra) = extra {
                    self.extra(*additional, extra, &child(path, "additional")?, true)?;
                }
            }
            (DeclaredKind::Array { items }, Node::Array(shape)) => {
                self.walk(*items, shape, &child(path, "items")?)?
            }
            (DeclaredKind::Number, Node::Primitive(Kind::Integer)) => (),
            (kind, Node::Primitive(observed)) if node_kind(kind) == Some(*observed) => (),
            _ => {
                self.emit(
                    path,
                    DeclaredObservationKind::TypeMismatch,
                    Some(declared),
                    Some(value),
                )?;
                self.scan(value, path)?;
            }
        }
        Ok(())
    }
    fn absent(
        &mut self,
        property: &crate::DeclaredProperty,
        path: &str,
    ) -> Result<(), ComparisonError> {
        if property.required() {
            let path = field(path, property.name())?;
            let node = self.resolve(property.target())?;
            self.emit(
                &path,
                DeclaredObservationKind::RequiredFieldNotObserved,
                node,
                None,
            )?;
        }
        Ok(())
    }
    fn extra(
        &mut self,
        policy: DeclaredAdditional,
        shape: &Shape,
        path: &str,
        unnamed: bool,
    ) -> Result<(), ComparisonError> {
        self.visit()?;
        // Unnamed observed members do not identify which declared property they
        // represent. They cannot prove that an additional-property rule failed.
        if unnamed {
            self.emit(
                path,
                DeclaredObservationKind::InsufficientEvidence,
                None,
                Some(shape),
            )?;
            return self.scan(shape, path);
        }
        match policy {
            DeclaredAdditional::Schema(id) => self.walk(id, shape, path),
            DeclaredAdditional::Forbidden => {
                self.emit(
                    path,
                    DeclaredObservationKind::UndeclaredFieldObserved,
                    None,
                    Some(shape),
                )?;
                self.scan(shape, path)
            }
            DeclaredAdditional::Allowed => self.scan(shape, path),
        }
    }
    fn scan(&mut self, shape: &Shape, path: &str) -> Result<(), ComparisonError> {
        self.visit()?;
        match &shape.node {
            Node::Unknown(_) => self.emit(
                path,
                DeclaredObservationKind::InsufficientEvidence,
                None,
                Some(shape),
            )?,
            Node::Object(fields, extra) => {
                for (name, value) in fields {
                    self.scan(value, &field(path, name)?)?;
                }
                if let Some(extra) = extra {
                    self.scan(extra, &child(path, "additional")?)?;
                }
            }
            Node::Array(items) => self.scan(items, &child(path, "items")?)?,
            Node::Union(alternatives) => {
                for (index, value) in alternatives.iter().enumerate() {
                    self.scan(value, &child(path, &format!("alternatives/{index}"))?)?;
                }
            }
            Node::Primitive(_) => (),
        }
        Ok(())
    }
}
fn unknown(shape: &Shape) -> Option<UnknownReason> {
    if let Node::Unknown(reason) = shape.node {
        Some(reason)
    } else {
        None
    }
}
fn node_kind(kind: &DeclaredKind) -> Option<Kind> {
    Some(match kind {
        DeclaredKind::Null => Kind::Null,
        DeclaredKind::Boolean => Kind::Boolean,
        DeclaredKind::Integer => Kind::Integer,
        DeclaredKind::Number => Kind::Number,
        DeclaredKind::String => Kind::String,
        DeclaredKind::Binary => Kind::Binary,
        DeclaredKind::Object { .. } => Kind::Object,
        DeclaredKind::Array { .. } => Kind::Array,
        DeclaredKind::Union { .. } => Kind::Union,
        DeclaredKind::Unknown { .. } => Kind::Unknown,
        DeclaredKind::Reference { .. } => return None,
    })
}
fn child(parent: &str, segment: &str) -> Result<String, ComparisonError> {
    if parent.chars().count() + 1 + segment.chars().count() > MAX_COMPARISON_PATH_SCALARS {
        return Err(ComparisonError::PathLimit);
    }
    Ok(format!("{parent}/{segment}"))
}
fn field(parent: &str, name: &str) -> Result<String, ComparisonError> {
    child(
        parent,
        &format!("fields/{}", name.replace('~', "~0").replace('/', "~1")),
    )
}
