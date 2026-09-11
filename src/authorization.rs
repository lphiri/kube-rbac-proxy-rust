use crate::config::*;
use anyhow::{anyhow, Result};
use http::Request;
use percent_encoding::percent_decode_str;

#[derive(Debug, Clone, Default)]
pub struct Identity {
    pub name: String,
    pub groups: Vec<String>,
}
#[derive(Debug, Clone, Default)]
pub struct Attributes {
    pub user: Identity,
    pub verb: String,
    pub namespace: String,
    pub api_group: String,
    pub api_version: String,
    pub resource: String,
    pub subresource: String,
    pub name: String,
    pub resource_request: bool,
    pub path: String,
}
fn kube_verb(method: &str) -> &str {
    match method {
        "GET" => "get",
        "POST" => "create",
        "PUT" => "update",
        "PATCH" => "patch",
        "DELETE" => "delete",
        "OPTIONS" => "options",
        "HEAD" => "head",
        _ => "*",
    }
}
fn wildcard(rule: &str, actual: &str) -> bool {
    rule.is_empty() || rule == actual
}
fn value(template: &str, v: &str, captures: &std::collections::HashMap<String, String>) -> String {
    let mut out = template.replace("{{ .Value }}", v);
    for (k, val) in captures {
        out = out.replace(&format!("{{{{ index .PathParams \"{k}\" }}}}"), val);
    }
    out
}
fn endpoint_value(
    template: &str,
    replacement: &str,
    header: &str,
    query: &str,
    method: &str,
    captures: &std::collections::HashMap<String, String>,
) -> String {
    value(template, replacement, captures)
        .replace("{{.FromHeader}}", header)
        .replace("{{ .FromHeader }}", header)
        .replace("{{.FromQueryString}}", query)
        .replace("{{ .FromQueryString }}", query)
        .replace("{{.FromMethod}}", method)
        .replace("{{ .FromMethod }}", method)
}
fn endpoint_match(pattern: &str, path: &str) -> Option<std::collections::HashMap<String, String>> {
    let clean = |input: &str| {
        let mut parts = Vec::new();
        for part in input.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop();
                }
                x => parts.push(x),
            }
        }
        format!("/{}", parts.join("/"))
    };
    let normalized_pattern = clean(pattern);
    let normalized_path = clean(path);
    let normalized_pattern = normalized_pattern.trim_end_matches('/');
    let normalized_path = normalized_path.trim_end_matches('/');
    let normalized_pattern = if normalized_pattern.is_empty() {
        "/"
    } else {
        normalized_pattern
    };
    let normalized_path = if normalized_path.is_empty() {
        "/"
    } else {
        normalized_path
    };
    let pp: Vec<_> = normalized_pattern.split('/').collect();
    let rp: Vec<_> = normalized_path.split('/').collect();
    if pp.len() != rp.len() {
        return None;
    }
    let mut out = std::collections::HashMap::new();
    for (p, r) in pp.iter().zip(rp.iter()) {
        if p.starts_with('{') && p.ends_with('}') {
            let n = &p[1..p.len() - 1];
            let valid_name = !n.is_empty()
                && n.chars().enumerate().all(|(i, c)| {
                    c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || c == '_'))
                });
            if !valid_name
                || out
                    .insert(
                        n.to_string(),
                        percent_decode_str(r).decode_utf8_lossy().into_owned(),
                    )
                    .is_some()
            {
                return None;
            }
        } else if *p != "*" && p != r {
            return None;
        }
    }
    Some(out)
}
pub fn attributes(
    cfg: &AuthorizationConfig,
    req: &Request<()>,
    identity: Identity,
) -> Result<Vec<Attributes>> {
    let path = req.uri().path();
    for endpoint in &cfg.endpoints {
        if let Some(captures) = endpoint_match(&endpoint.path, path) {
            let method = req.method().as_str().to_ascii_lowercase();
            let mapping = endpoint
                .mappings
                .iter()
                .find(|m| m.methods.iter().any(|x| x.eq_ignore_ascii_case(&method)))
                .ok_or_else(|| {
                    anyhow!("HTTP method not allowed for matched authorization endpoint")
                })?;
            let mut out = Vec::new();
            for rule in &mapping.resources {
                let mut ra = rule.resource_attributes.clone();
                let rewrite = endpoint_rewrites(req, &rule.rewrites)?;
                let (v, header, query) = rewrite.first().cloned().unwrap_or_default();
                let method_verb = kube_verb(req.method().as_str());
                ra.verb = endpoint_value(&ra.verb, &v, &header, &query, method_verb, &captures);
                ra.namespace =
                    endpoint_value(&ra.namespace, &v, &header, &query, method_verb, &captures);
                ra.api_group =
                    endpoint_value(&ra.api_group, &v, &header, &query, method_verb, &captures);
                ra.api_version =
                    endpoint_value(&ra.api_version, &v, &header, &query, method_verb, &captures);
                ra.resource =
                    endpoint_value(&ra.resource, &v, &header, &query, method_verb, &captures);
                ra.subresource =
                    endpoint_value(&ra.subresource, &v, &header, &query, method_verb, &captures);
                ra.name = endpoint_value(&ra.name, &v, &header, &query, method_verb, &captures);
                out.push(to_attr(&ra, req, identity.clone(), true));
            }
            return Ok(out);
        }
    }
    let verb = if cfg
        .resource_attributes
        .as_ref()
        .and_then(|x| (!x.verb.is_empty()).then_some(x.verb.clone()))
        .is_some()
    {
        cfg.resource_attributes.as_ref().unwrap().verb.clone()
    } else {
        kube_verb(req.method().as_str()).to_string()
    };
    if let Some(ra) = &cfg.resource_attributes {
        let values = if let Some(r) = &cfg.rewrites {
            collect(req, r)
        } else {
            vec![String::new()]
        };
        if cfg.rewrites.is_some() && values.is_empty() {
            return Ok(vec![]);
        }
        return Ok(values
            .into_iter()
            .map(|v| {
                let mut x = ra.clone();
                x.namespace = value(&x.namespace, &v, &Default::default());
                x.api_group = value(&x.api_group, &v, &Default::default());
                x.api_version = value(&x.api_version, &v, &Default::default());
                x.resource = value(&x.resource, &v, &Default::default());
                x.subresource = value(&x.subresource, &v, &Default::default());
                x.name = value(&x.name, &v, &Default::default());
                let mut a = to_attr(&x, req, identity.clone(), true);
                a.verb = verb.clone();
                a
            })
            .collect());
    }
    Ok(vec![Attributes {
        user: identity,
        verb,
        path: path.to_string(),
        ..Default::default()
    }])
}
fn collect(req: &Request<()>, r: &Rewrites) -> Vec<String> {
    let mut v = Vec::new();
    if let Some(q) = &r.by_query_parameter {
        for (k, x) in url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes()) {
            if k == q.name {
                v.push(x.into_owned());
            }
        }
    }
    if let Some(h) = &r.by_http_header {
        for x in req
            .headers()
            .get_all(&h.name)
            .iter()
            .filter_map(|x| x.to_str().ok())
        {
            v.push(x.to_string());
        }
    }
    v
}

pub fn validate_authorization_config(cfg: &AuthorizationConfig) -> Result<()> {
    for (endpoint_index, endpoint) in cfg.endpoints.iter().enumerate() {
        if endpoint.path.trim().is_empty() {
            return Err(anyhow!(
                "authorization.endpoints[{endpoint_index}]: path must be non-empty"
            ));
        }
        if endpoint.mappings.is_empty() {
            return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): mappings must contain at least one entry", endpoint.path));
        }
        let mut captures = std::collections::HashSet::new();
        for segment in endpoint.path.split('/') {
            if segment.contains(['{', '}']) {
                if !(segment.starts_with('{') && segment.ends_with('}') && segment.len() >= 3) {
                    return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): malformed path capture {:?}", endpoint.path, segment));
                }
                let name = &segment[1..segment.len() - 1];
                let valid = name.chars().enumerate().all(|(i, c)| {
                    c.is_ascii_alphabetic() || (i > 0 && (c.is_ascii_digit() || c == '_'))
                });
                if !valid {
                    return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): invalid path capture name {:?}", endpoint.path, name));
                }
                if !captures.insert(name) {
                    return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): duplicate path capture {:?}", endpoint.path, name));
                }
            }
        }
        for (mapping_index, mapping) in endpoint.mappings.iter().enumerate() {
            if mapping.methods.is_empty() {
                return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): mappings[{mapping_index}] must specify a non-empty methods list", endpoint.path));
            }
            if mapping.resources.is_empty() {
                return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): mappings[{mapping_index}] must contain at least one resource rule", endpoint.path));
            }
            for (resource_index, rule) in mapping.resources.iter().enumerate() {
                if let Some(header) = &rule.rewrites.by_http_header {
                    if header.name.trim().is_empty() {
                        return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): mappings[{mapping_index}].resources[{resource_index}].rewrites.byHttpHeader must specify a non-empty name", endpoint.path));
                    }
                }
                if let Some(query) = &rule.rewrites.by_query_parameter {
                    if query.name.trim().is_empty() {
                        return Err(anyhow!("authorization.endpoints[{endpoint_index}] (path {:?}): mappings[{mapping_index}].resources[{resource_index}].rewrites.byQueryParameter must specify a non-empty name", endpoint.path));
                    }
                }
            }
        }
    }
    for (index, rule) in cfg.static_rules.iter().enumerate() {
        if rule.resource_request != rule.path.is_empty() {
            return Err(anyhow!(
                "authorization.static[{index}]: resource requests must not include a path"
            ));
        }
    }
    Ok(())
}
fn endpoint_rewrites(req: &Request<()>, r: &Rewrites) -> Result<Vec<(String, String, String)>> {
    let header = r.by_http_header.as_ref().map(|h| {
        req.headers()
            .get(&h.name)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string()
    });
    let query = r.by_query_parameter.as_ref().map(|q| {
        url::form_urlencoded::parse(req.uri().query().unwrap_or("").as_bytes())
            .find(|(k, _)| k == &q.name)
            .map(|(_, v)| v.into_owned())
            .unwrap_or_default()
    });
    if let Some(h) = &r.by_http_header {
        if header.as_deref() == Some("") {
            return Err(anyhow!("required header {} is missing", h.name));
        }
    }
    if let Some(q) = &r.by_query_parameter {
        if query.as_deref() == Some("") {
            return Err(anyhow!("required query parameter {} is missing", q.name));
        }
    }
    let h = header.unwrap_or_default();
    let q = query.unwrap_or_default();
    if h.is_empty() && q.is_empty() {
        return Ok(Vec::new());
    }
    Ok(vec![(
        if !h.is_empty() { h.clone() } else { q.clone() },
        h,
        q,
    )])
}
fn to_attr(
    ra: &ResourceAttributes,
    req: &Request<()>,
    user: Identity,
    resource: bool,
) -> Attributes {
    Attributes {
        user,
        verb: if ra.verb.is_empty() {
            kube_verb(req.method().as_str()).to_string()
        } else {
            ra.verb.clone()
        },
        namespace: ra.namespace.clone(),
        api_group: ra.api_group.clone(),
        api_version: ra.api_version.clone(),
        resource: ra.resource.clone(),
        subresource: ra.subresource.clone(),
        name: ra.name.clone(),
        resource_request: resource,
        path: req.uri().path().to_string(),
    }
}
pub fn static_allows(rules: &[StaticRule], a: &Attributes) -> bool {
    rules.iter().any(|r| {
        wildcard(&r.user.name, &a.user.name)
            && wildcard(&r.verb, &a.verb)
            && wildcard(&r.namespace, &a.namespace)
            && wildcard(&r.api_group, &a.api_group)
            && wildcard(&r.resource, &a.resource)
            && wildcard(&r.subresource, &a.subresource)
            && wildcard(&r.name, &a.name)
            && wildcard(&r.path, &a.path)
            && r.resource_request == a.resource_request
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{
        Endpoint, Mapping, NamedValue, ResourceAttributes, Rewrites, Rule, StaticRule, UserRule,
    };
    use http::Method;

    fn request(method: Method, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }
    fn user() -> Identity {
        Identity {
            name: "system:foo".into(),
            groups: vec![],
        }
    }

    #[test]
    fn match_endpoint_has_exact_segment_semantics() {
        let cases = [
            ("/api/v1/jobs", "/api/v1/jobsabc", false),
            ("/api/v1/jobs/*", "/api/v1/jobs/123", true),
            ("/api/v1/jobs/*", "/api/v1/jobs/123/details", false),
            ("/api/*/jobs/*", "/api/v2/jobs/abc", true),
            ("/api/v1/jobs/*", "//api/v1/jobs/99/", true),
            ("/api/v1/jobs/*", "/api/v1/jobs/../jobs/99", true),
        ];
        for (pattern, path, expected) in cases {
            assert_eq!(
                endpoint_match(pattern, path).is_some(),
                expected,
                "{pattern} {path}"
            );
        }
    }

    #[test]
    fn named_capture_is_decoded_and_available_to_templates() {
        let cfg = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/api/{tenant}/jobs/{id}".into(),
                mappings: vec![Mapping {
                    methods: vec!["GET".into()],
                    resources: vec![Rule {
                        resource_attributes: ResourceAttributes {
                            namespace: "{{ index .PathParams \"tenant\" }}".into(),
                            name: "{{ index .PathParams \"id\" }}".into(),
                            resource: "jobs".into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }],
                }],
            }],
            ..Default::default()
        };
        let attrs = attributes(
            &cfg,
            &request(Method::GET, "/api/acme%20team/jobs/job-7"),
            user(),
        )
        .unwrap();
        assert_eq!(attrs[0].namespace, "acme team");
        assert_eq!(attrs[0].name, "job-7");
        assert_eq!(attrs[0].verb, "get");
    }

    #[test]
    fn endpoint_method_mismatch_is_an_error() {
        let cfg = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/events".into(),
                mappings: vec![Mapping {
                    methods: vec!["post".into()],
                    resources: vec![Rule {
                        resource_attributes: ResourceAttributes {
                            resource: "events".into(),
                            ..Default::default()
                        },
                        ..Default::default()
                    }],
                }],
            }],
            ..Default::default()
        };
        let err = attributes(&cfg, &request(Method::GET, "/events"), user()).unwrap_err();
        assert!(err.to_string().contains("method not allowed"));
    }

    #[test]
    fn endpoint_header_rewrite_and_missing_header() {
        let cfg = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/events".into(),
                mappings: vec![Mapping {
                    methods: vec!["post".into()],
                    resources: vec![Rule {
                        rewrites: Rewrites {
                            by_http_header: Some(NamedValue {
                                name: "X-Tenant".into(),
                            }),
                            ..Default::default()
                        },
                        resource_attributes: ResourceAttributes {
                            namespace: "{{.FromHeader}}".into(),
                            verb: "create".into(),
                            ..Default::default()
                        },
                    }],
                }],
            }],
            ..Default::default()
        };
        let req = Request::builder()
            .method(Method::POST)
            .uri("/events")
            .header("X-Tenant", "tenant-ns")
            .body(())
            .unwrap();
        let attrs = attributes(&cfg, &req, user()).unwrap();
        assert_eq!(attrs[0].namespace, "tenant-ns");
        assert_eq!(attrs[0].verb, "create");
        let err = attributes(&cfg, &request(Method::POST, "/events"), user()).unwrap_err();
        assert!(err.to_string().contains("required header"));
    }

    #[test]
    fn endpoint_templates_support_method_and_query_values() {
        let cfg = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/events".into(),
                mappings: vec![Mapping {
                    methods: vec!["post".into()],
                    resources: vec![Rule {
                        rewrites: Rewrites {
                            by_query_parameter: Some(NamedValue {
                                name: "tenant".into(),
                            }),
                            ..Default::default()
                        },
                        resource_attributes: ResourceAttributes {
                            namespace: "{{.FromQueryString}}".into(),
                            verb: "{{.FromMethod}}".into(),
                            ..Default::default()
                        },
                    }],
                }],
            }],
            ..Default::default()
        };
        let attrs = attributes(
            &cfg,
            &request(Method::POST, "/events?tenant=team-a"),
            user(),
        )
        .unwrap();
        assert_eq!(attrs[0].namespace, "team-a");
        assert_eq!(attrs[0].verb, "create");
    }

    #[test]
    fn format1_resource_and_non_resource_attributes() {
        let resource = AuthorizationConfig {
            resource_attributes: Some(ResourceAttributes {
                namespace: "tenant1".into(),
                api_version: "v1".into(),
                resource: "namespaces".into(),
                subresource: "metrics".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let attrs = attributes(&resource, &request(Method::GET, "/accounts"), user()).unwrap();
        assert!(attrs[0].resource_request);
        assert_eq!(attrs[0].namespace, "tenant1");
        let non_resource = attributes(
            &AuthorizationConfig::default(),
            &request(Method::GET, "/metrics"),
            user(),
        )
        .unwrap();
        assert!(!non_resource[0].resource_request);
        assert_eq!(non_resource[0].path, "/metrics");
    }

    #[test]
    fn format1_rewrites_support_query_headers_and_multiple_values() {
        let cfg = AuthorizationConfig {
            rewrites: Some(Rewrites {
                by_query_parameter: Some(NamedValue {
                    name: "namespace".into(),
                }),
                by_http_header: None,
            }),
            resource_attributes: Some(ResourceAttributes {
                namespace: "{{ .Value }}".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let attrs = attributes(
            &cfg,
            &request(Method::GET, "/metrics?namespace=one&namespace=two"),
            user(),
        )
        .unwrap();
        assert_eq!(attrs.len(), 2);
        assert_eq!(attrs[1].namespace, "two");
        let header_cfg = AuthorizationConfig {
            rewrites: Some(Rewrites {
                by_http_header: Some(NamedValue {
                    name: "X-Tenant".into(),
                }),
                ..Default::default()
            }),
            resource_attributes: Some(ResourceAttributes {
                namespace: "{{ .Value }}".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics")
            .header("X-Tenant", "one")
            .header("X-Tenant", "two")
            .body(())
            .unwrap();
        assert_eq!(attributes(&header_cfg, &req, user()).unwrap().len(), 2);

        let both = AuthorizationConfig {
            rewrites: Some(Rewrites {
                by_query_parameter: Some(NamedValue {
                    name: "tenant".into(),
                }),
                by_http_header: Some(NamedValue {
                    name: "X-Tenant".into(),
                }),
            }),
            resource_attributes: Some(ResourceAttributes {
                namespace: "{{ .Value }}".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let req = Request::builder()
            .method(Method::GET)
            .uri("/metrics?tenant=query")
            .header("X-Tenant", "header")
            .body(())
            .unwrap();
        let attrs = attributes(&both, &req, user()).unwrap();
        assert_eq!(attrs[0].namespace, "query");
        assert_eq!(attrs[1].namespace, "header");
    }

    #[test]
    fn endpoint_rules_take_precedence_over_format1_rules() {
        let cfg = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/events".into(),
                mappings: vec![Mapping {
                    methods: vec!["post".into()],
                    resources: vec![Rule {
                        rewrites: Rewrites {
                            by_http_header: Some(NamedValue {
                                name: "X-Tenant".into(),
                            }),
                            ..Default::default()
                        },
                        resource_attributes: ResourceAttributes {
                            namespace: "{{.FromHeader}}".into(),
                            resource: "status-events".into(),
                            verb: "create".into(),
                            ..Default::default()
                        },
                    }],
                }],
            }],
            rewrites: Some(Rewrites {
                by_query_parameter: Some(NamedValue {
                    name: "namespace".into(),
                }),
                ..Default::default()
            }),
            resource_attributes: Some(ResourceAttributes {
                namespace: "{{ .Value }}".into(),
                resource: "namespaces".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let req = Request::builder()
            .method(Method::POST)
            .uri("/events?namespace=wrong")
            .header("X-Tenant", "tenant-a")
            .body(())
            .unwrap();
        let attrs = attributes(&cfg, &req, user()).unwrap();
        assert_eq!(attrs.len(), 1);
        assert_eq!(attrs[0].namespace, "tenant-a");
        assert_eq!(attrs[0].resource, "status-events");
        assert_eq!(attrs[0].verb, "create");
    }

    #[test]
    fn http_methods_map_to_kubernetes_verbs() {
        assert_eq!(kube_verb("GET"), "get");
        assert_eq!(kube_verb("POST"), "create");
        assert_eq!(kube_verb("PUT"), "update");
        assert_eq!(kube_verb("PATCH"), "patch");
        assert_eq!(kube_verb("DELETE"), "delete");
        assert_eq!(kube_verb("OPTIONS"), "options");
        assert_eq!(kube_verb("HEAD"), "head");
        assert_eq!(kube_verb("TRACE"), "*");
    }

    #[test]
    fn static_authorization_matches_wildcards_and_resource_kind() {
        let rules = vec![StaticRule {
            path: "/metrics".into(),
            verb: "get".into(),
            resource_request: false,
            ..Default::default()
        }];
        let allowed = Attributes {
            user: user(),
            path: "/metrics".into(),
            verb: "get".into(),
            resource_request: false,
            ..Default::default()
        };
        assert!(static_allows(&rules, &allowed));
        let wrong_path = Attributes {
            path: "/api".into(),
            ..allowed.clone()
        };
        assert!(!static_allows(&rules, &wrong_path));
        let wrong_kind = Attributes {
            resource_request: true,
            ..allowed
        };
        assert!(!static_allows(&rules, &wrong_kind));
        let resource_rules = vec![StaticRule {
            user: UserRule {
                name: "system:foo".into(),
                ..Default::default()
            },
            resource: "namespaces".into(),
            verb: "get".into(),
            resource_request: true,
            ..Default::default()
        }];
        let resource = Attributes {
            user: user(),
            resource: "namespaces".into(),
            verb: "get".into(),
            resource_request: true,
            ..Default::default()
        };
        assert!(static_allows(&resource_rules, &resource));
    }

    #[test]
    fn authorization_validation_rejects_invalid_endpoint_shapes() {
        let invalid = [
            AuthorizationConfig {
                endpoints: vec![Endpoint {
                    path: "".into(),
                    ..Default::default()
                }],
                ..Default::default()
            },
            AuthorizationConfig {
                endpoints: vec![Endpoint {
                    path: "/p".into(),
                    mappings: vec![],
                }],
                ..Default::default()
            },
            AuthorizationConfig {
                endpoints: vec![Endpoint {
                    path: "/p".into(),
                    mappings: vec![Mapping {
                        methods: vec![],
                        ..Default::default()
                    }],
                }],
                ..Default::default()
            },
            AuthorizationConfig {
                endpoints: vec![Endpoint {
                    path: "/p".into(),
                    mappings: vec![Mapping {
                        methods: vec!["get".into()],
                        resources: vec![],
                    }],
                }],
                ..Default::default()
            },
            AuthorizationConfig {
                endpoints: vec![Endpoint {
                    path: "/p/{tenant-id}".into(),
                    mappings: vec![Mapping {
                        methods: vec!["get".into()],
                        resources: vec![Rule::default()],
                    }],
                }],
                ..Default::default()
            },
        ];
        for cfg in invalid {
            assert!(validate_authorization_config(&cfg).is_err());
        }
    }

    #[test]
    fn authorization_validation_rejects_duplicate_captures_and_invalid_rewrites() {
        let duplicate = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/{tenant}/reports/{tenant}".into(),
                mappings: vec![Mapping {
                    methods: vec!["get".into()],
                    resources: vec![Rule::default()],
                }],
            }],
            ..Default::default()
        };
        assert!(validate_authorization_config(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        let rewrite = AuthorizationConfig {
            endpoints: vec![Endpoint {
                path: "/p".into(),
                mappings: vec![Mapping {
                    methods: vec!["get".into()],
                    resources: vec![Rule {
                        rewrites: Rewrites {
                            by_http_header: Some(NamedValue { name: " ".into() }),
                            ..Default::default()
                        },
                        ..Default::default()
                    }],
                }],
            }],
            ..Default::default()
        };
        assert!(validate_authorization_config(&rewrite)
            .unwrap_err()
            .to_string()
            .contains("byHttpHeader"));
    }

    #[test]
    fn static_authorization_validation_requires_resource_rules_without_paths() {
        let invalid = AuthorizationConfig {
            static_rules: vec![StaticRule {
                path: "/metrics".into(),
                resource_request: true,
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(validate_authorization_config(&invalid).is_err());
        assert!(validate_authorization_config(&AuthorizationConfig::default()).is_ok());
    }
}
