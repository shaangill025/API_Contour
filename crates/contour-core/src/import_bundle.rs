//! Transient whole-document projection under independently trusted import policy.
use crate::{
    DeclaredContract, ImportError, ImportSelection, MAX_IMPORT_BYTES, Omission, OperationKey,
};
use serde_json::{Map, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

pub const MAX_IMPORT_MEMBERS: usize = 4096;
pub const MAX_IMPORT_GRAPH_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_IMPORT_GRAPH_NODES: usize = 65536;
pub const MAX_IMPORT_GRAPH_VISITS: usize = 262144;

/// Configured source paths are transient matching keys, never approved by upload.
pub struct ServiceImportPolicy<'a> {
    scope: [&'a str; 4],
    routes: BTreeMap<&'a str, &'a str>,
    names: &'a [&'a str],
    media: BTreeSet<&'a str>,
}
impl fmt::Debug for ServiceImportPolicy<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceImportPolicy")
    }
}
impl<'a> ServiceImportPolicy<'a> {
    pub fn new(
        scope: [&'a str; 4],
        routes: &'a [(&'a str, &'a str)],
        approved_names: &'a [&'a str],
        approved_media: &'a [&'a str],
    ) -> Result<Self, ImportError> {
        crate::import::validate_names(approved_names)?;
        if routes.len() > 1024 || approved_media.is_empty() || approved_media.len() > 64 {
            return Err(ImportError::Selection);
        }
        operation(scope, "request", "GET", "/")?;
        let mut mapped = BTreeMap::new();
        let mut targets = BTreeSet::new();
        for &(source, route) in routes {
            if !source.starts_with('/')
                || source.len() > 2048
                || source.chars().any(char::is_control)
                || mapped.insert(source, route).is_some()
                || !targets.insert(route)
            {
                return Err(ImportError::Selection);
            }
            operation(scope, "request", "GET", route)?;
        }
        let mut media = BTreeSet::new();
        for &value in approved_media {
            let valid_token = |part: &str| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
            };
            if value.len() > 128
                || !value
                    .split_once('/')
                    .is_some_and(|(a, b)| valid_token(a) && valid_token(b))
                || !media.insert(value)
            {
                return Err(ImportError::Selection);
            }
        }
        Ok(Self {
            scope,
            routes: mapped,
            names: approved_names,
            media,
        })
    }
}
fn operation<'a>(
    scope: [&'a str; 4],
    direction: &'a str,
    method: &'a str,
    route: &'a str,
) -> Result<OperationKey<'a>, ImportError> {
    OperationKey::from_components([
        scope[0], scope[1], scope[2], scope[3], "http", direction, method, route,
    ])
    .map_err(|_| ImportError::Selection)
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ResponseSelector {
    Status(u16),
    Class(u8),
    Default,
}
impl ResponseSelector {
    fn parse(value: &str) -> Result<Self, ImportError> {
        if value == "default" {
            return Ok(Self::Default);
        }
        let b = value.as_bytes();
        if b.len() == 3 && (b'1'..=b'5').contains(&b[0]) {
            if &b[1..] == b"XX" {
                return Ok(Self::Class(b[0] - b'0'));
            }
            if b[1..].iter().all(u8::is_ascii_digit) {
                return Ok(Self::Status(
                    u16::from(b[0] - b'0') * 100
                        + u16::from(b[1] - b'0') * 10
                        + u16::from(b[2] - b'0'),
                ));
            }
        }
        Err(ImportError::Selection)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImportBodySelector {
    Request,
    Response(ResponseSelector),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ImportBundleWarning {
    RemovedValue,
    UnsupportedConstruct,
    PartialImport,
}
pub struct DeclaredImportMember {
    graph: DeclaredContract,
    selector: ImportBodySelector,
    media_type: String,
}
impl fmt::Debug for DeclaredImportMember {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DeclaredImportMember")
    }
}
impl DeclaredImportMember {
    pub fn graph(&self) -> &DeclaredContract {
        &self.graph
    }
    pub fn selector(&self) -> ImportBodySelector {
        self.selector
    }
    pub fn media_type(&self) -> &str {
        &self.media_type
    }
}
pub struct DeclaredImportBundle {
    scope: [String; 4],
    members: Vec<DeclaredImportMember>,
    warnings: Vec<ImportBundleWarning>,
    graph_bytes: usize,
}
impl fmt::Debug for DeclaredImportBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeclaredImportBundle")
            .field("members", &self.members.len())
            .finish()
    }
}
impl DeclaredImportBundle {
    /// Trusted tenant, project, service and resolved environment, even when empty.
    pub fn scope(&self) -> [&str; 4] {
        self.scope.each_ref().map(String::as_str)
    }
    pub fn members(&self) -> &[DeclaredImportMember] {
        &self.members
    }
    pub fn warnings(&self) -> &[ImportBundleWarning] {
        &self.warnings
    }
    pub fn graph_bytes(&self) -> usize {
        self.graph_bytes
    }
}
fn object(value: &Value) -> Result<&Map<String, Value>, ImportError> {
    value.as_object().ok_or(ImportError::Invalid)
}

/// All supported body selections, or an error; never returns a truncated prefix.
/// Bodyless and unmodelled surfaces remain explicitly partial evidence.
pub fn import_service_declared(
    format: &str,
    bytes: &[u8],
    policy: &ServiceImportPolicy<'_>,
) -> Result<DeclaredImportBundle, ImportError> {
    if format != "openapi_json" {
        return Err(ImportError::UnsupportedFormat);
    }
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::Size);
    }
    let input = crate::import_json::parse(bytes)?;
    let root = object(&input)?;
    if root.get("openapi").and_then(Value::as_str) != Some("3.0.3") {
        return Err(ImportError::UnsupportedFormat);
    }
    let mut builder = Assembler {
        input: &input,
        policy,
        members: Vec::new(),
        warnings: BTreeSet::new(),
        bytes: 0,
        nodes: 0,
        remaining: MAX_IMPORT_GRAPH_VISITS,
    };
    builder.omitted(root, &["openapi", "paths", "components"]);
    if let Some(components) = root.get("components") {
        builder.omitted(object(components)?, &["schemas"]);
    }
    let paths = object(root.get("paths").ok_or(ImportError::Invalid)?)?;
    for (source, path) in paths {
        if source.starts_with("x-") {
            builder.partial();
            builder.removed();
            continue;
        }
        let route = *policy
            .routes
            .get(source.as_str())
            .ok_or(ImportError::Selection)?;
        let path = object(path)?;
        if path.contains_key("$ref") {
            return Err(ImportError::Reference);
        }
        const METHODS: [&str; 8] = [
            "delete", "get", "head", "options", "patch", "post", "put", "trace",
        ];
        builder.omitted(path, &METHODS);
        let mut has_operation = false;
        for method in METHODS {
            let Some(endpoint) = path.get(method) else {
                continue;
            };
            has_operation = true;
            let endpoint = object(endpoint)?;
            builder.omitted(endpoint, &["requestBody", "responses"]);
            let method = method.to_ascii_uppercase();
            if let Some(body) = endpoint.get("requestBody") {
                builder.body(body, source, route, &method, None)?;
            } else {
                builder.partial();
            }
            let responses = object(endpoint.get("responses").ok_or(ImportError::Invalid)?)?;
            if responses.is_empty() {
                return Err(ImportError::Invalid);
            }
            for (status, body) in responses {
                if status.starts_with("x-") {
                    builder.partial();
                    builder.removed();
                    continue;
                }
                ResponseSelector::parse(status)?;
                builder.body(body, source, route, &method, Some(status))?;
            }
        }
        if !has_operation {
            builder.partial();
        }
    }
    if builder.members.is_empty() {
        builder.partial();
    }
    Ok(DeclaredImportBundle {
        scope: policy.scope.map(str::to_owned),
        members: builder.members,
        warnings: builder.warnings.into_iter().collect(),
        graph_bytes: builder.bytes,
    })
}
struct Assembler<'a, 'p> {
    input: &'a Value,
    policy: &'a ServiceImportPolicy<'p>,
    members: Vec<DeclaredImportMember>,
    warnings: BTreeSet<ImportBundleWarning>,
    bytes: usize,
    nodes: usize,
    remaining: usize,
}
impl Assembler<'_, '_> {
    fn partial(&mut self) {
        self.warnings.insert(ImportBundleWarning::PartialImport);
        self.warnings
            .insert(ImportBundleWarning::UnsupportedConstruct);
    }
    fn removed(&mut self) {
        self.warnings.insert(ImportBundleWarning::RemovedValue);
    }
    fn omitted(&mut self, value: &Map<String, Value>, retained: &[&str]) {
        for key in value.keys().filter(|key| !retained.contains(&key.as_str())) {
            self.removed();
            if !matches!(
                key.as_str(),
                "info"
                    | "description"
                    | "summary"
                    | "operationId"
                    | "example"
                    | "examples"
                    | "tags"
                    | "externalDocs"
            ) {
                self.partial();
            }
        }
    }
    fn body(
        &mut self,
        value: &Value,
        source: &str,
        route: &str,
        method: &str,
        status: Option<&str>,
    ) -> Result<(), ImportError> {
        let body = object(value)?;
        if body.contains_key("$ref") {
            return Err(ImportError::Reference);
        }
        self.omitted(body, &["content"]);
        let Some(content) = body.get("content") else {
            self.partial();
            return Ok(());
        };
        let content = object(content)?;
        if content.is_empty() {
            self.partial();
        }
        for (media, value) in content {
            let approved = *self
                .policy
                .media
                .get(media.as_str())
                .ok_or(ImportError::Name)?;
            let media_object = object(value)?;
            self.omitted(media_object, &["schema"]);
            if !media_object.contains_key("schema") {
                self.partial();
                continue;
            }
            if self.members.len() == MAX_IMPORT_MEMBERS {
                return Err(ImportError::Graph);
            }
            let selector = match status {
                Some(status) => ImportBodySelector::Response(ResponseSelector::parse(status)?),
                None => ImportBodySelector::Request,
            };
            let key = operation(
                self.policy.scope,
                if status.is_some() {
                    "response"
                } else {
                    "request"
                },
                method,
                route,
            )?;
            let graph = crate::import_openapi::convert_budget(
                self.input,
                key,
                ImportSelection {
                    source_path: source,
                    media_type: approved,
                    response_status: status,
                },
                self.policy.names,
                &mut self.remaining,
            )?;
            let size = graph.to_wire_json().map_err(|_| ImportError::Graph)?.len();
            if size > MAX_IMPORT_GRAPH_BYTES.saturating_sub(self.bytes)
                || graph.nodes().len() > MAX_IMPORT_GRAPH_NODES.saturating_sub(self.nodes)
            {
                return Err(ImportError::Graph);
            }
            self.bytes += size;
            self.nodes += graph.nodes().len();
            for omission in graph.omissions() {
                match omission {
                    Omission::RemovedValue => self.removed(),
                    Omission::UnsupportedConstruct => self.partial(),
                }
            }
            self.members.push(DeclaredImportMember {
                graph,
                selector,
                media_type: approved.to_owned(),
            });
        }
        Ok(())
    }
}
