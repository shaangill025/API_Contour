//! Internal declared version containment. Checked names do not grant authorization.
use crate::{
    DeclaredAdditional as Additional, DeclaredContract, DeclaredKind as K, Kind,
    MAX_COMPARISON_DIFFERENCES, MAX_COMPARISON_PATH_BYTES, MAX_COMPARISON_PATH_SCALARS,
    MAX_COMPARISON_VISITS,
};
use std::{collections::BTreeSet, fmt};
mod wire;
pub use wire::{DeclaredComparisonCodecError, MAX_DECLARED_COMPARISON_BYTES};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredCompatibility {
    Compatible,
    Incompatible,
    Inconclusive,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredVersionError {
    OperationScope,
    UnsupportedDirection,
    WorkLimit,
    DifferenceLimit,
    PathLimit,
}
impl fmt::Display for DeclaredVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeclaredVersionError {}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredVersionDifferenceKind {
    TypeChanged,
    NullMembershipChanged,
    RequirednessChanged,
    FieldAdded,
    FieldRemoved,
    AdditionalPolicyChanged,
    InsufficientEvidence,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredAdditionalPolicy {
    Allowed,
    Forbidden,
    Schema,
}
fn policy(value: Additional) -> DeclaredAdditionalPolicy {
    match value {
        Additional::Allowed => DeclaredAdditionalPolicy::Allowed,
        Additional::Forbidden => DeclaredAdditionalPolicy::Forbidden,
        Additional::Schema(_) => DeclaredAdditionalPolicy::Schema,
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredVersionDifference {
    pub path: String,
    pub kind: DeclaredVersionDifferenceKind,
    /// Baseline/candidate labels never reverse for response comparison.
    pub baseline_kind: Option<Kind>,
    pub candidate_kind: Option<Kind>,
    pub baseline_required: Option<bool>,
    pub candidate_required: Option<bool>,
    pub baseline_includes_null: Option<bool>,
    pub candidate_includes_null: Option<bool>,
    pub baseline_additional: Option<DeclaredAdditionalPolicy>,
    pub candidate_additional: Option<DeclaredAdditionalPolicy>,
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredVersionComparison {
    compatibility: DeclaredCompatibility,
    differences: Vec<DeclaredVersionDifference>,
}
impl DeclaredVersionComparison {
    pub fn compatibility(&self) -> DeclaredCompatibility {
        self.compatibility
    }
    pub fn differences(&self) -> &[DeclaredVersionDifference] {
        &self.differences
    }
}
// Avoid exposing policy-dependent names in default diagnostics.
impl fmt::Debug for DeclaredVersionComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredVersionComparison")
    }
}
impl fmt::Debug for DeclaredVersionDifference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredVersionDifference")
    }
}
#[derive(Clone, Copy, Default)]
struct Normal {
    blocked: bool,
    uncertain: bool,
    null: bool,
    value: Option<u32>,
}
struct Budget {
    visits: usize,
    path_bytes: usize,
}
impl Budget {
    fn visit(&mut self) -> Result<(), DeclaredVersionError> {
        if self.visits == MAX_COMPARISON_VISITS {
            return Err(DeclaredVersionError::WorkLimit);
        }
        self.visits += 1;
        Ok(())
    }
}
fn index(graph: &DeclaredContract, id: u32) -> usize {
    graph
        .nodes()
        .binary_search_by_key(&id, |node| node.id())
        .expect("checked graph")
}
/// Normalize each node once using postorder, including otherwise unreachable nodes.
/// Unknown/omitted/general-union/recursive graphs deliberately yield no proof.
fn normalize(
    graph: &DeclaredContract,
    budget: &mut Budget,
) -> Result<(Vec<Normal>, bool), DeclaredVersionError> {
    let mut uncertain = !graph.omissions().is_empty();
    let mut colors = vec![0u8; graph.nodes().len()];
    let mut normal = vec![Normal::default(); graph.nodes().len()];
    for start in 0..graph.nodes().len() {
        if colors[start] == 2 {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((at, exit)) = stack.pop() {
            let node = &graph.nodes()[at];
            if exit {
                normal[at] = match node.kind() {
                    K::Null => Normal {
                        null: true,
                        ..Normal::default()
                    },
                    K::Unknown { .. } => Normal {
                        blocked: true,
                        uncertain: true,
                        ..Normal::default()
                    },
                    K::Reference { name } => {
                        let target =
                            index(graph, graph.definition(name).expect("checked reference"));
                        if colors[target] == 2 {
                            normal[target]
                        } else {
                            Normal {
                                blocked: true,
                                uncertain: true,
                                ..Normal::default()
                            }
                        }
                    }
                    K::Union { alternatives } => {
                        let mut value = Normal::default();
                        let mut nonnull = 0;
                        for target in alternatives {
                            budget.visit()?;
                            let at = index(graph, *target);
                            let child = normal[at];
                            value.blocked |= colors[at] != 2;
                            value.null |= child.null;
                            value.uncertain |= child.uncertain;
                            value.blocked |= child.blocked;
                            if child.value.is_some() {
                                nonnull += 1;
                                value.value = child.value;
                            }
                        }
                        value.blocked |= nonnull > 1;
                        value.uncertain |= value.blocked;
                        value
                    }
                    _ => Normal {
                        value: Some(node.id()),
                        ..Normal::default()
                    },
                };
                normal[at].uncertain |= !node.omissions().is_empty();
                uncertain |= normal[at].uncertain;
                colors[at] = 2;
                continue;
            }
            if colors[at] == 2 {
                continue;
            }
            budget.visit()?;
            // A cycle may close on a structural edge after a named reference.
            // Never re-enter gray nodes; comparison tracks active resolved pairs.
            if colors[at] == 1 {
                uncertain = true;
                continue;
            }
            colors[at] = 1;
            stack.push((at, true));
            let targets: Vec<u32> = match node.kind() {
                K::Reference { name } => vec![graph.definition(name).expect("checked reference")],
                K::Array { items } => vec![*items],
                K::Union { alternatives } => alternatives.clone(),
                K::Object {
                    properties,
                    additional,
                } => properties
                    .iter()
                    .map(|p| p.target())
                    .chain(match additional {
                        Additional::Schema(id) => Some(*id),
                        _ => None,
                    })
                    .collect(),
                _ => Vec::new(),
            };
            for target in targets.into_iter().rev() {
                budget.visit()?;
                stack.push((index(graph, target), false));
            }
        }
    }
    Ok((normal, uncertain))
}
#[derive(Clone, Copy)]
enum Value {
    Node(u32),
    Any,
    Never,
}
fn additional(value: Additional) -> Value {
    match value {
        Additional::Allowed => Value::Any,
        Additional::Forbidden => Value::Never,
        Additional::Schema(id) => Value::Node(id),
    }
}
fn kind(graph: &DeclaredContract, value: Value) -> Option<Kind> {
    let Value::Node(id) = value else {
        return None;
    };
    Some(match graph.node(id).expect("checked node").kind() {
        K::Null => Kind::Null,
        K::Boolean => Kind::Boolean,
        K::Integer => Kind::Integer,
        K::Number => Kind::Number,
        K::String => Kind::String,
        K::Binary => Kind::Binary,
        K::Object { .. } => Kind::Object,
        K::Array { .. } => Kind::Array,
        K::Union { .. } => Kind::Union,
        _ => Kind::Unknown,
    })
}
fn label(graph: &DeclaredContract, normalized: &[Normal], value: Value) -> Option<Kind> {
    let Value::Node(id) = value else {
        return None;
    };
    let normal = normalized[index(graph, id)];
    if normal.blocked {
        Some(Kind::Unknown)
    } else {
        normal
            .value
            .map_or(Some(Kind::Null), |id| kind(graph, Value::Node(id)))
    }
}
fn child(path: &str, segment: &str) -> Result<String, DeclaredVersionError> {
    let next = format!("{path}/{segment}");
    if next.chars().count() > MAX_COMPARISON_PATH_SCALARS {
        return Err(DeclaredVersionError::PathLimit);
    }
    Ok(next)
}
enum Work {
    Compare(Value, Value, String, bool),
    Leave(u32, u32),
}
struct Walker<'a> {
    source: &'a DeclaredContract,
    target: &'a DeclaredContract,
    reverse: bool,
    source_normal: Vec<Normal>,
    target_normal: Vec<Normal>,
    budget: Budget,
    differences: Vec<DeclaredVersionDifference>,
    pending: Vec<Work>,
    active: BTreeSet<(u32, u32)>,
    incompatible: bool,
    pending_bytes: usize,
}
impl Walker<'_> {
    fn emit(
        &mut self,
        path: &str,
        kind: DeclaredVersionDifferenceKind,
        source: Value,
        target: Value,
    ) -> Result<(), DeclaredVersionError> {
        if self.differences.len() == MAX_COMPARISON_DIFFERENCES {
            return Err(DeclaredVersionError::DifferenceLimit);
        }
        if path.len() > MAX_COMPARISON_PATH_BYTES - self.budget.path_bytes {
            return Err(DeclaredVersionError::PathLimit);
        }
        self.budget.path_bytes += path.len();
        let (a, b) = (
            label(self.source, &self.source_normal, source),
            label(self.target, &self.target_normal, target),
        );
        self.differences.push(DeclaredVersionDifference {
            path: path.into(),
            kind,
            baseline_kind: if self.reverse { b } else { a },
            candidate_kind: if self.reverse { a } else { b },
            baseline_required: None,
            candidate_required: None,
            baseline_includes_null: None,
            candidate_includes_null: None,
            baseline_additional: None,
            candidate_additional: None,
        });
        Ok(())
    }
    fn push(
        &mut self,
        a: Value,
        b: Value,
        path: String,
        report: bool,
    ) -> Result<(), DeclaredVersionError> {
        // Bound queued allocations separately from returned finding paths.
        if path.len() > MAX_COMPARISON_PATH_BYTES - self.pending_bytes {
            return Err(DeclaredVersionError::PathLimit);
        }
        self.budget.visit()?;
        self.pending_bytes += path.len();
        self.pending.push(Work::Compare(a, b, path, report));
        Ok(())
    }
}

/// Request: baseline subset candidate. Response: candidate subset baseline.
/// This is internal structural evidence, not an approved baseline or operation-set
/// comparison. Errors return no partial findings; unsupported evidence dominates.
pub fn compare_declared_versions(
    baseline: &DeclaredContract,
    candidate: &DeclaredContract,
) -> Result<DeclaredVersionComparison, DeclaredVersionError> {
    if baseline.operation() != candidate.operation() {
        return Err(DeclaredVersionError::OperationScope);
    }
    let reverse = match baseline.operation().components()[5] {
        "request" => false,
        "response" => true,
        _ => return Err(DeclaredVersionError::UnsupportedDirection),
    };
    let (source, target) = if reverse {
        (candidate, baseline)
    } else {
        (baseline, candidate)
    };
    let mut walker = Walker {
        source,
        target,
        reverse,
        source_normal: Vec::new(),
        target_normal: Vec::new(),
        budget: Budget {
            visits: 0,
            path_bytes: 0,
        },
        differences: Vec::new(),
        pending: Vec::new(),
        active: BTreeSet::new(),
        pending_bytes: 0,
        incompatible: false,
    };
    let (sn, su) = normalize(source, &mut walker.budget)?;
    let (tn, tu) = normalize(target, &mut walker.budget)?;
    let uncertain = su || tu;
    walker.source_normal = sn;
    walker.target_normal = tn;
    if uncertain {
        walker.emit(
            "#",
            DeclaredVersionDifferenceKind::InsufficientEvidence,
            Value::Node(source.root()),
            Value::Node(target.root()),
        )?;
    }
    walker.push(
        Value::Node(source.root()),
        Value::Node(target.root()),
        "#".into(),
        true,
    )?;
    while let Some(work) = walker.pending.pop() {
        let (a, b, path, report) = match work {
            Work::Compare(a, b, path, report) => (a, b, path, report),
            Work::Leave(a, b) => {
                walker.active.remove(&(a, b));
                continue;
            }
        };
        walker.pending_bytes -= path.len();
        use DeclaredVersionDifferenceKind as D;
        match (a, b) {
            (Value::Never, _) | (_, Value::Any) => continue,
            (_, Value::Never) | (Value::Any, _) => {
                walker.incompatible = true;
                continue;
            }
            _ => (),
        }
        let (Value::Node(ai), Value::Node(bi)) = (a, b) else {
            unreachable!()
        };
        let (an, bn) = (
            walker.source_normal[index(source, ai)],
            walker.target_normal[index(target, bi)],
        );
        if an.blocked || bn.blocked {
            continue;
        }
        if an.null != bn.null {
            walker.incompatible |= an.null && !bn.null;
            if report {
                walker.emit(&path, D::NullMembershipChanged, a, b)?;
                let finding = walker.differences.last_mut().expect("emitted finding");
                finding.baseline_includes_null = Some(if reverse { bn.null } else { an.null });
                finding.candidate_includes_null = Some(if reverse { an.null } else { bn.null });
            }
        }
        let (Some(ai), Some(bi)) = (an.value, bn.value) else {
            walker.incompatible |= an.value.is_some();
            if report && an.value.is_some() != bn.value.is_some() {
                walker.emit(&path, D::TypeChanged, a, b)?;
            }
            continue;
        };
        // Leave markers release only the current ancestry, not a global visited
        // set: repeated references at independent paths still produce findings.
        if !walker.active.insert((ai, bi)) {
            continue;
        }
        walker.pending.push(Work::Leave(ai, bi));
        let (a, b) = (Value::Node(ai), Value::Node(bi));
        if report && kind(source, a) != kind(target, b) {
            walker.emit(&path, D::TypeChanged, a, b)?;
        }
        match (
            source.node(ai).expect("checked node").kind(),
            target.node(bi).expect("checked node").kind(),
        ) {
            (
                K::Object {
                    properties: ap,
                    additional: aa,
                },
                K::Object {
                    properties: bp,
                    additional: ba,
                },
            ) => {
                let next = child(&path, "additional")?;
                if report && policy(*aa) != policy(*ba) {
                    walker.emit(
                        &next,
                        D::AdditionalPolicyChanged,
                        additional(*aa),
                        additional(*ba),
                    )?;
                    let finding = walker.differences.last_mut().expect("emitted finding");
                    finding.baseline_additional = Some(policy(if reverse { *ba } else { *aa }));
                    finding.candidate_additional = Some(policy(if reverse { *aa } else { *ba }));
                }
                walker.push(additional(*aa), additional(*ba), next, report)?;
                let (mut i, mut j) = (0, 0);
                while i < ap.len() || j < bp.len() {
                    walker.budget.visit()?;
                    let name = match (ap.get(i), bp.get(j)) {
                        (Some(x), Some(y)) => x.name().min(y.name()),
                        (Some(x), None) => x.name(),
                        (None, Some(y)) => y.name(),
                        _ => unreachable!(),
                    };
                    let av = ap.get(i).filter(|p| p.name() == name);
                    let bv = bp.get(j).filter(|p| p.name() == name);
                    let x = av.map_or(additional(*aa), |p| Value::Node(p.target()));
                    let y = bv.map_or(additional(*ba), |p| Value::Node(p.target()));
                    let next = child(
                        &path,
                        &format!("fields/{}", name.replace('~', "~0").replace('/', "~1")),
                    )?;
                    let (ar, br) = (av.map(|p| p.required()), bv.map(|p| p.required()));
                    walker.incompatible |= br == Some(true) && ar != Some(true);
                    if report && (av.is_some() != bv.is_some() || ar != br) {
                        let change = if av.is_some() != bv.is_some() {
                            if bv.is_some() != reverse {
                                D::FieldAdded
                            } else {
                                D::FieldRemoved
                            }
                        } else {
                            D::RequirednessChanged
                        };
                        walker.emit(
                            &next,
                            change,
                            av.map_or(Value::Never, |p| Value::Node(p.target())),
                            bv.map_or(Value::Never, |p| Value::Node(p.target())),
                        )?;
                        let finding = walker.differences.last_mut().expect("emitted finding");
                        finding.baseline_required = if reverse { br } else { ar };
                        finding.candidate_required = if reverse { ar } else { br };
                    }
                    walker.push(x, y, next, report && av.is_some() && bv.is_some())?;
                    i += usize::from(av.is_some());
                    j += usize::from(bv.is_some());
                }
            }
            (K::Array { items: a }, K::Array { items: b }) => walker.push(
                Value::Node(*a),
                Value::Node(*b),
                child(&path, "items")?,
                report,
            )?,
            (K::Integer, K::Number) => (),
            _ if kind(source, a) == kind(target, b) => (),
            _ => walker.incompatible = true,
        }
    }
    walker
        .differences
        .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
    Ok(DeclaredVersionComparison {
        compatibility: if uncertain {
            DeclaredCompatibility::Inconclusive
        } else if walker.incompatible {
            DeclaredCompatibility::Incompatible
        } else {
            DeclaredCompatibility::Compatible
        },
        differences: walker.differences,
    })
}
