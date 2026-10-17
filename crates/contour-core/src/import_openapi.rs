use crate::{OperationKey, declared::*, import::*};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
type Object = Map<String, Value>;
fn object(v: &Value) -> Result<&Object, ImportError> {
    v.as_object().ok_or(ImportError::Invalid)
}
fn field<'a>(v: &'a Value, key: &str) -> Result<&'a Value, ImportError> {
    object(v)?.get(key).ok_or(ImportError::Selection)
}
fn flag(o: &Object, key: &str) -> Result<bool, ImportError> {
    o.get(key)
        .map_or(Ok(false), |v| v.as_bool().ok_or(ImportError::Invalid))
}
pub(crate) fn convert(
    input: &Value,
    operation: OperationKey<'_>,
    selection: ImportSelection<'_>,
    names: &[&str],
) -> Result<DeclaredContract, ImportError> {
    convert_budget(input, operation, selection, names, &mut 32768)
}
pub(crate) fn convert_budget(
    input: &Value,
    operation: OperationKey<'_>,
    selection: ImportSelection<'_>,
    names: &[&str],
    remaining: &mut usize,
) -> Result<DeclaredContract, ImportError> {
    if field(input, "openapi")?.as_str() != Some("3.0.3") {
        return Err(ImportError::UnsupportedFormat);
    }
    let components = operation.components();
    if components[4] != "http"
        || !matches!(components[5], "request" | "response")
        || (components[5] == "response") != selection.response_status.is_some()
    {
        return Err(ImportError::Selection);
    }
    let path = field(field(input, "paths")?, selection.source_path)?;
    if object(path)?.contains_key("$ref") {
        return Err(ImportError::Reference);
    }
    let endpoint = field(path, &components[6].to_ascii_lowercase())?;
    let body = match selection.response_status {
        None => field(endpoint, "requestBody")?,
        Some(status) => field(field(endpoint, "responses")?, status)?,
    };
    if object(body)?.contains_key("$ref") {
        return Err(ImportError::Reference);
    }
    let media = field(field(body, "content")?, selection.media_type)?;
    let schema = field(media, "schema")?;
    let mut builder = Builder {
        input,
        names,
        response: selection.response_status.is_some(),
        nodes: Vec::new(),
        refs: BTreeMap::new(),
        pending: Vec::new(),
        edges: 1,
        visits: 0,
        remaining,
    };
    let root = builder.schema(schema, 0)?;
    let mut definitions = Vec::new();
    let mut next = 0;
    while next < builder.pending.len() {
        let (source, generated) = builder.pending[next].clone();
        let target = builder.schema(builder.target(&source)?, 0)?;
        definitions.push(DeclaredDefinition {
            name: generated,
            target,
        });
        next += 1;
    }
    let omissions = builder
        .nodes
        .iter()
        .flat_map(|n| n.omissions.iter().copied())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let model = DeclaredContract {
        operation: components.map(str::to_owned),
        root,
        nodes: builder.nodes,
        definitions,
        omissions,
    }
    .checked()
    .map_err(|_| ImportError::Graph)?;
    let bytes = model.to_wire_json().map_err(|_| ImportError::Graph)?;
    DeclaredContract::from_wire_json(&bytes).map_err(|_| ImportError::Graph)
}
struct Builder<'a, 'b> {
    input: &'a Value,
    names: &'a [&'a str],
    response: bool,
    nodes: Vec<DeclaredNode>,
    refs: BTreeMap<String, String>,
    pending: Vec<(String, String)>,
    edges: usize,
    visits: usize,
    remaining: &'b mut usize,
}
impl<'a> Builder<'a, '_> {
    fn visit(&mut self) -> Result<(), ImportError> {
        if self.visits == 32768 || *self.remaining == 0 {
            return Err(ImportError::Graph);
        }
        self.visits += 1;
        *self.remaining -= 1;
        Ok(())
    }
    fn edge(&mut self, count: usize) -> Result<(), ImportError> {
        if count > MAX_DECLARED_EDGES.saturating_sub(self.edges) {
            return Err(ImportError::Graph);
        }
        self.edges += count;
        Ok(())
    }
    fn node(&mut self, kind: DeclaredKind, omissions: Vec<Omission>) -> Result<u32, ImportError> {
        if self.nodes.len() == MAX_DECLARED_NODES {
            return Err(ImportError::Graph);
        }
        let id = self.nodes.len() as u32;
        self.nodes.push(DeclaredNode {
            id,
            kind,
            omissions,
        });
        Ok(id)
    }
    fn target(&self, name: &str) -> Result<&'a Value, ImportError> {
        self.input
            .get("components")
            .and_then(|v| v.get("schemas"))
            .and_then(|v| v.get(name))
            .filter(|v| v.is_object())
            .ok_or(ImportError::Reference)
    }
    fn reference(&mut self, value: &Value) -> Result<String, ImportError> {
        let name = reference_name(value)?;
        self.target(&name)?;
        if let Some(generated) = self.refs.get(&name) {
            return Ok(generated.clone());
        }
        if self.pending.len() == MAX_DECLARED_DEFINITIONS {
            return Err(ImportError::Graph);
        }
        self.edge(1)?;
        let generated = format!("d{}", self.pending.len());
        self.refs.insert(name.clone(), generated.clone());
        self.pending.push((name, generated.clone()));
        Ok(generated)
    }
    fn flags(&mut self, mut value: &'a Value) -> Result<(bool, bool), ImportError> {
        let mut seen = BTreeSet::new();
        loop {
            self.visit()?;
            let o = object(value)?;
            let Some(reference) = o.get("$ref") else {
                return Ok((flag(o, "readOnly")?, flag(o, "writeOnly")?));
            };
            let name = reference_name(reference)?;
            if !seen.insert(name.clone()) {
                return Ok((false, false));
            }
            if seen.len() > MAX_DECLARED_DEFINITIONS {
                return Err(ImportError::Graph);
            }
            value = self.target(&name)?;
        }
    }
    fn schema(&mut self, value: &'a Value, depth: usize) -> Result<u32, ImportError> {
        if depth > 64 {
            return Err(ImportError::Graph);
        }
        self.visit()?;
        let o = object(value)?;
        if let Some(reference) = o.get("$ref") {
            let name = self.reference(reference)?;
            self.edge(1)?;
            let omissions = if o.len() > 1 {
                vec![Omission::RemovedValue]
            } else {
                vec![]
            };
            return self.node(DeclaredKind::Reference { name }, omissions);
        }
        let read = flag(o, "readOnly")?;
        let write = flag(o, "writeOnly")?;
        if read && write {
            return Err(ImportError::Invalid);
        }
        let nullable = flag(o, "nullable")?;
        let mut omissions = BTreeSet::new();
        for key in o.keys() {
            match key.as_str() {
                "type"
                | "properties"
                | "required"
                | "additionalProperties"
                | "items"
                | "nullable" => (),
                "readOnly" | "writeOnly" => {
                    if read || write {
                        omissions.insert(Omission::UnsupportedConstruct);
                    }
                }
                "title" | "description" | "example" | "default" | "externalDocs" => {
                    omissions.insert(Omission::RemovedValue);
                }
                _ => {
                    omissions.insert(Omission::RemovedValue);
                    omissions.insert(Omission::UnsupportedConstruct);
                }
            }
        }
        let unsupported = ["allOf", "oneOf", "anyOf", "not"]
            .iter()
            .any(|k| o.contains_key(*k));
        let ty = o
            .get("type")
            .map(|v| v.as_str().ok_or(ImportError::Invalid))
            .transpose()?;
        let kind = if unsupported {
            DeclaredKind::Unknown {
                reason: DeclaredUnknown::Unsupported,
            }
        } else {
            match ty {
                None => DeclaredKind::Unknown {
                    reason: DeclaredUnknown::Unspecified,
                },
                Some("boolean") => DeclaredKind::Boolean,
                Some("integer") => DeclaredKind::Integer,
                Some("number") => DeclaredKind::Number,
                Some("string") => DeclaredKind::String,
                Some("array") => {
                    self.edge(1)?;
                    DeclaredKind::Array {
                        items: self
                            .schema(o.get("items").ok_or(ImportError::Invalid)?, depth + 1)?,
                    }
                }
                Some("object") => {
                    let props = o.get("properties").map(object).transpose()?;
                    if props.map_or(0, Object::len) > 256 {
                        return Err(ImportError::Graph);
                    }
                    let mut required = BTreeSet::new();
                    if let Some(list) = o.get("required") {
                        let list = list.as_array().ok_or(ImportError::Invalid)?;
                        if list.is_empty() || list.len() > 256 {
                            return Err(ImportError::Invalid);
                        }
                        for name in list {
                            let name = name.as_str().ok_or(ImportError::Invalid)?;
                            if !props.is_some_and(|props| props.contains_key(name))
                                || !required.insert(name)
                            {
                                return Err(ImportError::Invalid);
                            }
                        }
                    }
                    let mut properties = Vec::new();
                    for (name, schema) in props.into_iter().flatten() {
                        if !self.names.contains(&name.as_str()) {
                            return Err(ImportError::Name);
                        }
                        let (read, write) = self.flags(schema)?;
                        self.edge(1)?;
                        let target = self.schema(schema, depth + 1)?;
                        properties.push(DeclaredProperty {
                            name: name.clone(),
                            required: required.contains(name.as_str())
                                && !(read && !self.response || write && self.response),
                            target,
                        });
                    }
                    let additional = match o.get("additionalProperties") {
                        None | Some(Value::Bool(true)) => DeclaredAdditional::Allowed,
                        Some(Value::Bool(false)) => DeclaredAdditional::Forbidden,
                        Some(v) => {
                            self.edge(1)?;
                            DeclaredAdditional::Schema(self.schema(v, depth + 1)?)
                        }
                    };
                    DeclaredKind::Object {
                        properties,
                        additional,
                    }
                }
                _ => return Err(ImportError::Invalid),
            }
        };
        // Type-specific keywords outside their represented type are not silently lost.
        if (o.contains_key("properties")
            || o.contains_key("required")
            || o.contains_key("additionalProperties"))
            && ty != Some("object")
            || o.contains_key("items") && ty != Some("array")
        {
            omissions.insert(Omission::UnsupportedConstruct);
        }
        let base = self.node(kind, omissions.into_iter().collect())?;
        if nullable && ty.is_some() && !unsupported {
            self.edge(2)?;
            let null = self.node(DeclaredKind::Null, vec![])?;
            self.node(
                DeclaredKind::Union {
                    alternatives: vec![base, null],
                },
                vec![],
            )
        } else {
            Ok(base)
        }
    }
}

fn reference_name(value: &Value) -> Result<String, ImportError> {
    let raw = value.as_str().ok_or(ImportError::Reference)?;
    let part = raw
        .strip_prefix("#/components/schemas/")
        .ok_or(ImportError::Reference)?;
    if part.is_empty() || part.contains('/') {
        return Err(ImportError::Reference);
    }
    let mut name = String::new();
    let mut chars = part.chars();
    while let Some(ch) = chars.next() {
        name.push(if ch == '~' {
            match chars.next() {
                Some('0') => '~',
                Some('1') => '/',
                _ => return Err(ImportError::Reference),
            }
        } else {
            ch
        });
    }
    Ok(name)
}
