//! Observed differences are evidence, never declared compatibility or requiredness.
use crate::{Kind, Node, OperationObservation, Shape, UnknownReason};
use std::fmt;

pub const MAX_COMPARISON_PATH_SCALARS: usize = 1024;
pub const MAX_COMPARISON_DIFFERENCES: usize = 10_000;
pub const MAX_COMPARISON_PATH_BYTES: usize = 1_048_576;
pub const MAX_COMPARISON_VISITS: usize = 32_768;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedCompatibility {
    Inconclusive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedDifferenceKind {
    FieldAdded,
    FieldAbsent,
    TypeChanged,
    NullMembershipChanged,
    InsufficientEvidence,
    UnsupportedConstruct,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComparisonError {
    OperationScope,
    ParserProfile,
    PathLimit,
    DifferenceLimit,
    WorkLimit,
}
impl fmt::Display for ComparisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ComparisonError {}

#[derive(Clone, PartialEq, Eq)]
pub struct ObservedDifference {
    pub path: String,
    pub kind: ObservedDifferenceKind,
    pub left_kind: Option<Kind>,
    pub right_kind: Option<Kind>,
    pub left_unknown: Option<UnknownReason>,
    pub right_unknown: Option<UnknownReason>,
    pub left_includes_null: Option<bool>,
    pub right_includes_null: Option<bool>,
}
impl fmt::Debug for ObservedDifference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObservedDifference")
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct ObservedComparison {
    differences: Vec<ObservedDifference>,
}
impl ObservedComparison {
    /// Equal known observations still do not establish a declared contract.
    pub fn compatibility(&self) -> ObservedCompatibility {
        ObservedCompatibility::Inconclusive
    }
    pub fn differences(&self) -> &[ObservedDifference] {
        &self.differences
    }
}
impl fmt::Debug for ObservedComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ObservedComparison")
    }
}

/// Compare baseline (left) with candidate (right). Checked syntax is not caller
/// authorization: adapters must obtain both observations through authorized scope.
/// Full operation identity includes direction and environment; deployment, source,
/// collector and policy revision do not by themselves prevent observed comparison.
/// Every success is inconclusive. Errors return no truncated comparison.
pub fn compare_observed(
    left: &OperationObservation<'_>,
    right: &OperationObservation<'_>,
) -> Result<ObservedComparison, ComparisonError> {
    if left.key != right.key {
        return Err(ComparisonError::OperationScope);
    }
    if left.parser_profile != right.parser_profile
        || left.canonicalization_version != right.canonicalization_version
    {
        return Err(ComparisonError::ParserProfile);
    }
    let mut walker = Walker {
        differences: Vec::new(),
        path_bytes: 0,
        visits: 0,
    };
    // Incomplete observations can contain known fields. Preserve those differences
    // while making the whole-observation evidence limitation explicit.
    if (left.completeness != "complete"
        || right.completeness != "complete"
        || !left.reasons.is_empty()
        || !right.reasons.is_empty()
        || left.sample_numerator != left.sample_denominator
        || right.sample_numerator != right.sample_denominator
        || left.route_uncertain
        || right.route_uncertain)
        && unknown(left.structure).is_none()
        && unknown(right.structure).is_none()
    {
        walker.emit(
            "#",
            ObservedDifferenceKind::InsufficientEvidence,
            Some(left.structure),
            Some(right.structure),
        )?;
    }
    walker.walk(left.structure, right.structure, "#")?;
    Ok(ObservedComparison {
        differences: walker.differences,
    })
}
struct Walker {
    differences: Vec<ObservedDifference>,
    path_bytes: usize,
    visits: usize,
}
impl Walker {
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
        kind: ObservedDifferenceKind,
        left: Option<&Shape>,
        right: Option<&Shape>,
    ) -> Result<(), ComparisonError> {
        if self.differences.len() == MAX_COMPARISON_DIFFERENCES {
            return Err(ComparisonError::DifferenceLimit);
        }
        if path.len() > MAX_COMPARISON_PATH_BYTES - self.path_bytes {
            return Err(ComparisonError::PathLimit);
        }
        self.path_bytes += path.len();
        self.differences.push(ObservedDifference {
            path: path.to_owned(),
            kind,
            left_kind: left.map(Shape::kind),
            right_kind: right.map(Shape::kind),
            left_unknown: left.and_then(unknown),
            right_unknown: right.and_then(unknown),
            left_includes_null: left.and_then(null_membership),
            right_includes_null: right.and_then(null_membership),
        });
        Ok(())
    }
    fn walk(&mut self, left: &Shape, right: &Shape, path: &str) -> Result<(), ComparisonError> {
        self.visit()?;
        if unknown(left).is_some() || unknown(right).is_some() {
            return self.emit(
                path,
                ObservedDifferenceKind::InsufficientEvidence,
                Some(left),
                Some(right),
            );
        }
        if let (Some(a), Some(b)) = (null_membership(left), null_membership(right)) {
            if a != b {
                self.emit(
                    path,
                    ObservedDifferenceKind::NullMembershipChanged,
                    Some(left),
                    Some(right),
                )?;
            }
        }
        if matches!(left.node, Node::Union(_)) || matches!(right.node, Node::Union(_)) {
            if let (Some(a), Some(b)) = (nullable_base(left), nullable_base(right)) {
                return self.walk(a, b, path);
            }
            if let (Node::Union(a), Node::Union(b)) = (&left.node, &right.node) {
                // Normalized order permits exact equality alignment. No general
                // union subtyping or quadratic alternative cross-product is attempted.
                let mut equal = a.len() == b.len();
                if equal {
                    for (a, b) in a.iter().zip(b) {
                        if !self.same(a, b)? {
                            equal = false;
                            break;
                        }
                    }
                }
                if equal {
                    for (index, (a, b)) in a.iter().zip(b).enumerate() {
                        self.walk(a, b, &child(path, &format!("alternatives/{index}"))?)?;
                    }
                    return Ok(());
                }
            }
            self.emit(
                path,
                ObservedDifferenceKind::UnsupportedConstruct,
                Some(left),
                Some(right),
            )?;
            self.scan_unknown(left, path, true)?;
            return self.scan_unknown(right, path, false);
        }
        match (&left.node, &right.node) {
            (Node::Object(a, extra_a), Node::Object(b, extra_b)) => {
                let (mut ai, mut bi) = (0, 0);
                while ai < a.len() || bi < b.len() {
                    match (a.get(ai), b.get(bi)) {
                        (Some((an, av)), Some((bn, bv))) if an == bn => {
                            self.walk(av, bv, &field(path, an)?)?;
                            ai += 1;
                            bi += 1;
                        }
                        (Some((an, av)), Some((bn, _))) if an.as_bytes() < bn.as_bytes() => {
                            self.unpaired(av, &field(path, an)?, true)?;
                            ai += 1;
                        }
                        (Some((an, av)), None) => {
                            self.unpaired(av, &field(path, an)?, true)?;
                            ai += 1;
                        }
                        (_, Some((bn, bv))) => {
                            self.unpaired(bv, &field(path, bn)?, false)?;
                            bi += 1;
                        }
                        (None, None) => break,
                    }
                }
                match (extra_a, extra_b) {
                    (Some(a), Some(b)) => self.walk(a, b, &child(path, "additional")?)?,
                    (None, None) => {}
                    (a, b) => {
                        let path = child(path, "additional")?;
                        self.emit(
                            &path,
                            ObservedDifferenceKind::InsufficientEvidence,
                            a.as_deref(),
                            b.as_deref(),
                        )?;
                        if let Some(a) = a {
                            if unknown(a).is_none() {
                                self.scan_unknown(a, &path, true)?;
                            }
                        }
                        if let Some(b) = b {
                            if unknown(b).is_none() {
                                self.scan_unknown(b, &path, false)?;
                            }
                        }
                    }
                }
            }
            (Node::Array(a), Node::Array(b)) => self.walk(a, b, &child(path, "items")?)?,
            (Node::Primitive(a), Node::Primitive(b)) if a == b => {}
            _ => {
                self.emit(
                    path,
                    ObservedDifferenceKind::TypeChanged,
                    Some(left),
                    Some(right),
                )?;
                self.scan_unknown(left, path, true)?;
                self.scan_unknown(right, path, false)?;
            }
        }
        Ok(())
    }
    // Every recursive equality step consumes the same traversal budget as the
    // diff walk. No hidden recursive Shape equality can bypass WorkLimit.
    fn same(&mut self, left: &Shape, right: &Shape) -> Result<bool, ComparisonError> {
        self.visit()?;
        match (&left.node, &right.node) {
            (Node::Primitive(a), Node::Primitive(b)) => Ok(a == b),
            (Node::Unknown(a), Node::Unknown(b)) => Ok(a == b),
            (Node::Array(a), Node::Array(b)) => self.same(a, b),
            (Node::Object(a, extra_a), Node::Object(b, extra_b)) => {
                if a.len() != b.len() {
                    return Ok(false);
                }
                for ((an, av), (bn, bv)) in a.iter().zip(b) {
                    if an != bn || !self.same(av, bv)? {
                        return Ok(false);
                    }
                }
                match (extra_a, extra_b) {
                    (Some(a), Some(b)) => self.same(a, b),
                    (None, None) => Ok(true),
                    _ => Ok(false),
                }
            }
            (Node::Union(a), Node::Union(b)) => {
                if a.len() != b.len() {
                    return Ok(false);
                }
                for (a, b) in a.iter().zip(b) {
                    if !self.same(a, b)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    fn unpaired(&mut self, shape: &Shape, path: &str, left: bool) -> Result<(), ComparisonError> {
        self.emit(
            path,
            if left {
                ObservedDifferenceKind::FieldAbsent
            } else {
                ObservedDifferenceKind::FieldAdded
            },
            left.then_some(shape),
            (!left).then_some(shape),
        )?;
        self.scan_unknown(shape, path, left)
    }
    fn scan_unknown(
        &mut self,
        shape: &Shape,
        path: &str,
        left: bool,
    ) -> Result<(), ComparisonError> {
        self.visit()?;
        match &shape.node {
            Node::Unknown(_) => self.emit(
                path,
                ObservedDifferenceKind::InsufficientEvidence,
                left.then_some(shape),
                (!left).then_some(shape),
            )?,
            Node::Object(fields, extra) => {
                for (name, shape) in fields {
                    self.scan_unknown(shape, &field(path, name)?, left)?;
                }
                if let Some(extra) = extra {
                    self.scan_unknown(extra, &child(path, "additional")?, left)?;
                }
            }
            Node::Array(items) => self.scan_unknown(items, &child(path, "items")?, left)?,
            Node::Union(alternatives) => {
                for (index, shape) in alternatives.iter().enumerate() {
                    self.scan_unknown(
                        shape,
                        &child(path, &format!("alternatives/{index}"))?,
                        left,
                    )?;
                }
            }
            Node::Primitive(_) => {}
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
fn null_membership(shape: &Shape) -> Option<bool> {
    match &shape.node {
        Node::Unknown(_) => None,
        Node::Primitive(Kind::Null) => Some(true),
        Node::Union(alternatives) => {
            if alternatives.iter().any(|shape| shape.kind() == Kind::Null) {
                Some(true)
            } else if alternatives
                .iter()
                .any(|shape| shape.kind() == Kind::Unknown)
            {
                None
            } else {
                Some(false)
            }
        }
        _ => Some(false),
    }
}
// Only nullable single-base unions have an unambiguous structural counterpart.
fn nullable_base(shape: &Shape) -> Option<&Shape> {
    match &shape.node {
        Node::Union(alternatives)
            if alternatives.len() == 2 && null_membership(shape) == Some(true) =>
        {
            alternatives.iter().find(|shape| shape.kind() != Kind::Null)
        }
        Node::Union(_) | Node::Primitive(Kind::Null) => None,
        _ => Some(shape),
    }
}
fn child(parent: &str, segment: &str) -> Result<String, ComparisonError> {
    let base = parent;
    if base.chars().count() + 1 + segment.chars().count() > MAX_COMPARISON_PATH_SCALARS {
        return Err(ComparisonError::PathLimit);
    }
    Ok(format!("{base}/{segment}"))
}
fn field(parent: &str, name: &str) -> Result<String, ComparisonError> {
    child(
        parent,
        &format!("fields/{}", name.replace('~', "~0").replace('/', "~1")),
    )
}
