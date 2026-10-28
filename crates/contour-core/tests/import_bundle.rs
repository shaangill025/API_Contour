use contour_core::{
    ImportBodySelector, ImportBundleWarning, ImportError, ImportSelection, MAX_IMPORT_GRAPH_BYTES,
    MAX_IMPORT_GRAPH_NODES, OperationKey, ResponseSelector, ServiceImportPolicy, import_declared,
    import_service_declared,
};
use serde_json::{Value, json};
const U: &str = "00000000-0000-0000-0000-000000000001";
fn input(schema: Value) -> Value {
    json!({"openapi":"3.0.3","paths":{"/raw-secret":{"post":{
        "requestBody":{"content":{"application/json":{"schema":schema.clone()}}},
        "responses":{"200":{"content":{"application/json":{"schema":schema}}}}
    }}}})
}
fn run(value: &Value) -> Result<contour_core::DeclaredImportBundle, ImportError> {
    let routes = [("/raw-secret", "/orders")];
    let policy = ServiceImportPolicy::new([U; 4], &routes, &["id"], &["application/json"])?;
    import_service_declared("openapi_json", &serde_json::to_vec(value).unwrap(), &policy)
}
#[test]
fn enumerates_every_direction_status_and_media_deterministically() {
    let routes = [("/raw-secret", "/orders"), ("/other", "/items")];
    let policy = ServiceImportPolicy::new(
        [U; 4],
        &routes,
        &["id"],
        &["application/json", "text/plain"],
    )
    .unwrap();
    let body = json!({"content":{"text/plain":{"schema":{"type":"string"}},"application/json":{"schema":{"type":"integer"}}}});
    let mut doc = input(json!({"type":"string"}));
    doc["paths"]["/raw-secret"]["post"]["responses"] =
        json!({"404":body,"200":body,"2XX":body,"default":body});
    doc["paths"]["/other"] = json!({"get":{"responses":{"200":body}}});
    let bundle =
        import_service_declared("openapi_json", &serde_json::to_vec(&doc).unwrap(), &policy)
            .unwrap();
    assert_eq!(bundle.members().len(), 11);
    assert_eq!(
        bundle
            .members()
            .iter()
            .filter(|m| m.selector() == ImportBodySelector::Request)
            .count(),
        1
    );
    for selector in [
        ResponseSelector::Status(404),
        ResponseSelector::Class(2),
        ResponseSelector::Default,
    ] {
        assert_eq!(
            bundle
                .members()
                .iter()
                .filter(|m| m.selector() == ImportBodySelector::Response(selector))
                .count(),
            2
        );
    }
    let snapshot = |b: &contour_core::DeclaredImportBundle| {
        b.members()
            .iter()
            .map(|m| {
                (
                    m.selector(),
                    m.media_type().to_owned(),
                    m.graph().to_wire_json().unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    fn reverse_keys(value: &Value) -> String {
        match value {
            Value::Object(map) => format!(
                "{{{}}}",
                map.iter()
                    .rev()
                    .map(|(key, value)| format!(
                        "{}:{}",
                        serde_json::to_string(key).unwrap(),
                        reverse_keys(value)
                    ))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Value::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(reverse_keys)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            value => serde_json::to_string(value).unwrap(),
        }
    }
    let reordered = reverse_keys(&doc);
    assert_ne!(reordered, serde_json::to_string(&doc).unwrap());
    let again = import_service_declared("openapi_json", reordered.as_bytes(), &policy).unwrap();
    assert_eq!(snapshot(&bundle), snapshot(&again));
    assert_eq!(
        bundle.graph_bytes(),
        bundle
            .members()
            .iter()
            .map(|m| m.graph().to_wire_json().unwrap().len())
            .sum::<usize>()
    );
}
#[test]
fn uploaded_paths_names_and_media_never_authorize_themselves() {
    let mut doc = input(json!({"type":"object","properties":{"secret-name":{"type":"string"}}}));
    assert_eq!(run(&doc).unwrap_err(), ImportError::Name);
    doc = input(json!({"type":"string"}));
    doc["paths"]["/unapproved"] = doc["paths"]["/raw-secret"].clone();
    assert_eq!(run(&doc).unwrap_err(), ImportError::Selection);
    doc = input(json!({"type":"string"}));
    doc["paths"]["/raw-secret"]["post"]["requestBody"]["content"]["application/secret"] =
        json!({"schema":{"type":"string"}});
    assert_eq!(run(&doc).unwrap_err(), ImportError::Name);
    for routes in [
        vec![("/a", "/x"), ("/a", "/y")],
        vec![("/a", "/x"), ("/b", "/x")],
    ] {
        assert_eq!(
            ServiceImportPolicy::new([U; 4], &routes, &[], &["application/json"]).unwrap_err(),
            ImportError::Selection
        );
    }
}

#[test]
fn empty_partial_import_retains_the_resolved_scope() {
    let scope = [U, U, U, "00000000-0000-0000-0000-000000000002"];
    let policy = ServiceImportPolicy::new(scope, &[], &[], &["application/json"]).unwrap();
    let bundle = import_service_declared(
        "openapi_json",
        br#"{"openapi":"3.0.3","paths":{}}"#,
        &policy,
    )
    .unwrap();
    assert!(bundle.members().is_empty());
    assert_eq!(bundle.scope(), scope);
    assert!(
        bundle
            .warnings()
            .contains(&ImportBundleWarning::PartialImport)
    );
    assert!(!format!("{bundle:?}").contains(U));
}
#[test]
fn removes_values_and_raw_selectors_from_all_output_and_debug() {
    let mut doc = input(json!({"$ref":"#/components/schemas/secret-component"}));
    doc["info"] = json!({"title":"secret-title","version":"secret-version"});
    doc["x-private"] = json!({"secret-extension":"secret-value"});
    doc["components"] = json!({"schemas":{"secret-component":{"type":"object","description":"secret-description",
        "properties":{"id":{"type":"string","default":"secret-default","example":"secret-example"}}}}});
    let bundle = run(&doc).unwrap();
    for member in bundle.members() {
        let wire = String::from_utf8(member.graph().to_wire_json().unwrap()).unwrap();
        assert!(!wire.contains("secret"));
        assert!(!format!("{member:?}").contains("secret"));
    }
    assert!(!format!("{bundle:?}").contains("secret"));
    assert!(
        bundle
            .warnings()
            .contains(&ImportBundleWarning::RemovedValue)
    );
    assert!(
        bundle
            .warnings()
            .contains(&ImportBundleWarning::PartialImport)
    );
}
#[test]
fn rejects_invalid_input_and_keeps_bodyless_surfaces_partial() {
    let routes = [("/raw-secret", "/orders")];
    let policy = ServiceImportPolicy::new([U; 4], &routes, &[], &["application/json"]).unwrap();
    assert_eq!(
        import_service_declared(
            "openapi_json",
            br#"{"openapi":"3.0.3","openapi":"3.0.3","paths":{}}"#,
            &policy
        )
        .unwrap_err(),
        ImportError::Invalid
    );
    assert_eq!(
        import_service_declared("graphql_sdl", b"", &policy).unwrap_err(),
        ImportError::UnsupportedFormat
    );
    assert_eq!(
        run(&input(json!({"$ref":"https://invalid.example/secret"}))).unwrap_err(),
        ImportError::Reference
    );
    let mut doc = input(json!({"type":"string"}));
    doc["paths"]["/raw-secret"]["post"]["responses"] =
        json!({"secret-status":{"content":{"application/json":{"schema":{"type":"string"}}}}});
    assert_eq!(run(&doc).unwrap_err(), ImportError::Selection);
    doc["paths"]["/raw-secret"]["post"] = json!({"parameters":[{"name":"secret","in":"query"}],"responses":{"204":{"description":"secret"}}});
    let bundle = run(&doc).unwrap();
    assert!(bundle.members().is_empty());
    assert!(
        bundle
            .warnings()
            .contains(&ImportBundleWarning::PartialImport)
    );
}
fn repeated(
    schema: Value,
    names: &[String],
    count: usize,
) -> Result<contour_core::DeclaredImportBundle, ImportError> {
    let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    let routes = [("/raw-secret", "/orders")];
    let policy = ServiceImportPolicy::new([U; 4], &routes, &refs, &["application/json"])?;
    let responses=(100..100+count).map(|n|(n.to_string(),json!({"content":{"application/json":{"schema":{"$ref":"#/components/schemas/root"}}}}))).collect::<serde_json::Map<_,_>>();
    let doc = json!({"openapi":"3.0.3","paths":{"/raw-secret":{"get":{"responses":responses}}},"components":{"schemas":{"root":schema}}});
    import_service_declared("openapi_json", &serde_json::to_vec(&doc).unwrap(), &policy)
}
#[test]
fn aggregate_nodes_and_bytes_fail_without_returning_a_prefix() {
    for long in [false, true] {
        let names = (0..256)
            .map(|n| {
                if long {
                    format!("f{n:03}{}", "x".repeat(60))
                } else {
                    format!("f{n:03}")
                }
            })
            .collect::<Vec<_>>();
        let schema = json!({"type":"object","properties":names.iter().map(|n|(n.clone(),json!({"type":"string"}))).collect::<serde_json::Map<_,_>>()});
        let one = repeated(schema.clone(), &names, 1).unwrap();
        let graph = one.members()[0].graph();
        let bytes = graph.to_wire_json().unwrap().len();
        let nodes = graph.nodes().len();
        let count = if long {
            MAX_IMPORT_GRAPH_BYTES / bytes + 1
        } else {
            MAX_IMPORT_GRAPH_NODES / nodes + 1
        };
        assert!(count < 500);
        if long {
            assert!(count * nodes <= MAX_IMPORT_GRAPH_NODES);
        } else {
            assert!(count * bytes <= MAX_IMPORT_GRAPH_BYTES);
        }
        assert_eq!(
            repeated(schema, &names, count).unwrap_err(),
            ImportError::Graph
        );
    }
}
#[test]
fn aggregate_member_limit_preserves_each_individual_graph_limit() {
    let paths = (0..65).map(|i| format!("/p{i}")).collect::<Vec<_>>();
    let routes = paths
        .iter()
        .map(|p| (p.as_str(), p.as_str()))
        .collect::<Vec<_>>();
    let media = (0..8)
        .map(|i| format!("application/test{i}"))
        .collect::<Vec<_>>();
    let labels = media.iter().map(String::as_str).collect::<Vec<_>>();
    let policy = ServiceImportPolicy::new([U; 4], &routes, &[], &labels).unwrap();
    let content = media
        .iter()
        .map(|m| (m.clone(), json!({"schema":{"type":"string"}})))
        .collect::<serde_json::Map<_, _>>();
    let endpoint =
        json!({"requestBody":{"content":content},"responses":{"204":{"description":"no body"}}});
    let methods = [
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ]
    .into_iter()
    .map(|m| (m.to_owned(), endpoint.clone()))
    .collect::<serde_json::Map<_, _>>();
    let doc = json!({"openapi":"3.0.3","paths":paths.iter().map(|p|(p.clone(),json!(methods))).collect::<serde_json::Map<_,_>>()});
    assert_eq!(
        import_service_declared("openapi_json", &serde_json::to_vec(&doc).unwrap(), &policy)
            .unwrap_err(),
        ImportError::Graph
    );
}
#[test]
fn shared_reference_work_budget_is_not_reset_for_each_member() {
    let names = (0..256).map(|n| format!("f{n:03}")).collect::<Vec<_>>();
    let refs = names.iter().map(String::as_str).collect::<Vec<_>>();
    let mut schemas = serde_json::Map::new();
    for i in 0..100 {
        schemas.insert(
            format!("d{i}"),
            if i == 99 {
                json!({"type":"string"})
            } else {
                json!({"$ref":format!("#/components/schemas/d{}",i+1)})
            },
        );
    }
    schemas.insert("root".into(),json!({"type":"object","properties":names.iter().map(|n|(n.clone(),json!({"$ref":"#/components/schemas/d0"}))).collect::<serde_json::Map<_,_>>() }));
    let mut doc = input(json!({"$ref":"#/components/schemas/root"}));
    doc["components"] = json!({"schemas":schemas});
    let operation =
        OperationKey::from_components([U, U, U, U, "http", "response", "POST", "/orders"]).unwrap();
    assert!(
        import_declared(
            "openapi_json",
            &serde_json::to_vec(&doc).unwrap(),
            operation,
            ImportSelection {
                source_path: "/raw-secret",
                media_type: "application/json",
                response_status: Some("200")
            },
            &refs
        )
        .is_ok()
    );
    doc["paths"]["/raw-secret"]["post"]["responses"]=json!((200..211).map(|n|(n.to_string(),json!({"content":{"application/json":{"schema":{"$ref":"#/components/schemas/root"}}}}))).collect::<serde_json::Map<_,_>>());
    let routes = [("/raw-secret", "/orders")];
    let policy = ServiceImportPolicy::new([U; 4], &routes, &refs, &["application/json"]).unwrap();
    assert_eq!(
        import_service_declared("openapi_json", &serde_json::to_vec(&doc).unwrap(), &policy)
            .unwrap_err(),
        ImportError::Graph
    );
}
