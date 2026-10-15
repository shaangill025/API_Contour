//! Checked flat declared graph. Syntax and local names are not import authorization.
use crate::OperationKey;
use std::{collections::BTreeSet, fmt};

pub const MAX_DECLARED_BYTES: usize = 1_048_576;
pub const MAX_DECLARED_NODES: usize = 4096;
pub const MAX_DECLARED_EDGES: usize = 32768;
pub const MAX_DECLARED_DEFINITIONS: usize = 256;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredError {
    Size,
    Invalid,
    Duplicate,
    Reference,
    Edges,
    Cycle,
    Operation,
    Omissions,
}
impl fmt::Display for DeclaredError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DeclaredError {}
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Omission {
    RemovedValue,
    UnsupportedConstruct,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclaredUnknown {
    Unsupported,
    Omitted,
    Unspecified,
}
/// Null membership is represented by Null nodes/unions, never a second flag.
#[derive(Clone, PartialEq, Eq)]
pub enum DeclaredKind {
    Null,
    Boolean,
    Integer,
    Number,
    String,
    Binary,
    Object {
        properties: Vec<DeclaredProperty>,
        additional: DeclaredAdditional,
    },
    Array {
        items: u32,
    },
    Union {
        alternatives: Vec<u32>,
    },
    Reference {
        name: String,
    },
    Unknown {
        reason: DeclaredUnknown,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeclaredAdditional {
    Allowed,
    Forbidden,
    Schema(u32),
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredProperty {
    pub(crate) name: String,
    pub(crate) required: bool,
    pub(crate) target: u32,
}
impl DeclaredProperty {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn required(&self) -> bool {
        self.required
    }
    pub fn target(&self) -> u32 {
        self.target
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredNode {
    pub(crate) id: u32,
    pub(crate) kind: DeclaredKind,
    pub(crate) omissions: Vec<Omission>,
}
impl DeclaredNode {
    pub fn id(&self) -> u32 {
        self.id
    }
    pub fn kind(&self) -> &DeclaredKind {
        &self.kind
    }
    pub fn omissions(&self) -> &[Omission] {
        &self.omissions
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredDefinition {
    pub(crate) name: String,
    pub(crate) target: u32,
}
impl DeclaredDefinition {
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn target(&self) -> u32 {
        self.target
    }
}
#[derive(Clone, PartialEq, Eq)]
pub struct DeclaredContract {
    pub(crate) operation: [String; 8],
    pub(crate) root: u32,
    pub(crate) nodes: Vec<DeclaredNode>,
    pub(crate) definitions: Vec<DeclaredDefinition>,
    pub(crate) omissions: Vec<Omission>,
}
impl fmt::Debug for DeclaredContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredContract")
    }
}
impl DeclaredContract {
    pub fn operation(&self) -> OperationKey<'_> {
        // Constructed only after the shared operation validator succeeds.
        OperationKey {
            components: self.operation.each_ref().map(String::as_str),
        }
    }
    pub fn root(&self) -> u32 {
        self.root
    }
    pub fn nodes(&self) -> &[DeclaredNode] {
        &self.nodes
    }
    pub fn definitions(&self) -> &[DeclaredDefinition] {
        &self.definitions
    }
    pub fn omissions(&self) -> &[Omission] {
        &self.omissions
    }
    pub fn node(&self, id: u32) -> Option<&DeclaredNode> {
        self.nodes
            .binary_search_by_key(&id, |node| node.id)
            .ok()
            .map(|index| &self.nodes[index])
    }
    pub fn definition(&self, name: &str) -> Option<u32> {
        self.definitions
            .binary_search_by(|definition| definition.name.as_bytes().cmp(name.as_bytes()))
            .ok()
            .map(|index| self.definitions[index].target)
    }
    pub(crate) fn checked(mut self) -> Result<Self, DeclaredError> {
        OperationKey::from_components(self.operation.each_ref().map(String::as_str))
            .map_err(|_| DeclaredError::Operation)?;
        if self.nodes.is_empty()
            || self.nodes.len() > MAX_DECLARED_NODES
            || self.definitions.len() > MAX_DECLARED_DEFINITIONS
        {
            return Err(DeclaredError::Size);
        }
        self.nodes.sort_unstable_by_key(|node| node.id);
        self.definitions
            .sort_unstable_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        if self.nodes.windows(2).any(|pair| pair[0].id == pair[1].id)
            || self
                .definitions
                .windows(2)
                .any(|pair| pair[0].name == pair[1].name)
        {
            return Err(DeclaredError::Duplicate);
        }
        let ids = self
            .nodes
            .iter()
            .map(|node| node.id)
            .collect::<BTreeSet<_>>();
        if !ids.contains(&self.root)
            || self
                .definitions
                .iter()
                .any(|definition| !ids.contains(&definition.target))
        {
            return Err(DeclaredError::Reference);
        }
        let definitions = self
            .definitions
            .iter()
            .map(|definition| definition.name.as_str())
            .collect::<BTreeSet<_>>();
        let mut edges = 1 + self.definitions.len();
        let mut summary = BTreeSet::new();
        let mut adjacency = Vec::new();
        for node in &mut self.nodes {
            unique_omissions(&mut node.omissions)?;
            summary.extend(node.omissions.iter().copied());
            if matches!(
                node.kind,
                DeclaredKind::Unknown {
                    reason: DeclaredUnknown::Omitted
                }
            ) && !node.omissions.contains(&Omission::RemovedValue)
                || matches!(
                    node.kind,
                    DeclaredKind::Unknown {
                        reason: DeclaredUnknown::Unsupported
                    }
                ) && !node.omissions.contains(&Omission::UnsupportedConstruct)
            {
                return Err(DeclaredError::Omissions);
            }

            let mut targets = Vec::new();
            match &mut node.kind {
                DeclaredKind::Object {
                    properties,
                    additional,
                } => {
                    properties.sort_unstable_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
                    if properties.len() > 256
                        || properties
                            .windows(2)
                            .any(|pair| pair[0].name == pair[1].name)
                    {
                        return Err(DeclaredError::Duplicate);
                    }
                    targets.extend(properties.iter().map(|property| property.target));
                    if let DeclaredAdditional::Schema(target) = additional {
                        targets.push(*target);
                    }
                }
                DeclaredKind::Array { items } => targets.push(*items),
                DeclaredKind::Union { alternatives } => {
                    alternatives.sort_unstable();
                    if !(2..=64).contains(&alternatives.len())
                        || alternatives.windows(2).any(|pair| pair[0] == pair[1])
                    {
                        return Err(DeclaredError::Duplicate);
                    }
                    targets.extend(alternatives.iter().copied());
                }
                DeclaredKind::Reference { name } => {
                    if !definitions.contains(name.as_str()) {
                        return Err(DeclaredError::Reference);
                    }
                    edges += 1;
                }
                _ => (),
            }
            edges += targets.len();
            if edges > MAX_DECLARED_EDGES {
                return Err(DeclaredError::Edges);
            }
            if targets.iter().any(|target| !ids.contains(target)) {
                return Err(DeclaredError::Reference);
            }
            adjacency.push(targets);
        }
        // Structural edges must be acyclic. Every recursive path crosses an
        // explicit named Reference, whose checked target remains unexpanded.
        let mut incoming = vec![0usize; self.nodes.len()];
        let index = |id: &u32| {
            self.nodes
                .binary_search_by_key(id, |node| node.id)
                .expect("checked edge")
        };
        for targets in &adjacency {
            for target in targets {
                incoming[index(target)] += 1;
            }
        }
        let mut ready = incoming
            .iter()
            .enumerate()
            .filter_map(|(index, count)| (*count == 0).then_some(index))
            .collect::<Vec<_>>();
        let mut visited = 0;
        while let Some(node) = ready.pop() {
            visited += 1;
            for target in &adjacency[node] {
                let next = index(target);
                incoming[next] -= 1;
                if incoming[next] == 0 {
                    ready.push(next);
                }
            }
        }
        if visited != self.nodes.len() {
            return Err(DeclaredError::Cycle);
        }
        unique_omissions(&mut self.omissions)?;
        if self.omissions.iter().copied().collect::<BTreeSet<_>>() != summary {
            return Err(DeclaredError::Omissions);
        }
        Ok(self)
    }
}
fn unique_omissions(values: &mut [Omission]) -> Result<(), DeclaredError> {
    values.sort_unstable();
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DeclaredError::Duplicate);
    }
    Ok(())
}
