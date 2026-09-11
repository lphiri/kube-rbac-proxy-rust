use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ConfigFile {
    #[serde(default)]
    pub authorization: AuthorizationConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AuthorizationConfig {
    pub rewrites: Option<Rewrites>,
    #[serde(rename = "resourceAttributes")]
    pub resource_attributes: Option<ResourceAttributes>,
    #[serde(rename = "static", default)]
    pub static_rules: Vec<StaticRule>,
    #[serde(default)]
    pub endpoints: Vec<Endpoint>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rewrites {
    #[serde(rename = "byQueryParameter")]
    pub by_query_parameter: Option<NamedValue>,
    #[serde(rename = "byHttpHeader")]
    pub by_http_header: Option<NamedValue>,
}
#[derive(Debug, Clone, Deserialize)]
pub struct NamedValue {
    pub name: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ResourceAttributes {
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "apiGroup", default)]
    pub api_group: String,
    #[serde(rename = "apiVersion", default)]
    pub api_version: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub subresource: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub verb: String,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct UserRule {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub groups: Vec<String>,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct StaticRule {
    #[serde(default)]
    pub user: UserRule,
    #[serde(default)]
    pub verb: String,
    #[serde(default)]
    pub namespace: String,
    #[serde(rename = "apiGroup", default)]
    pub api_group: String,
    #[serde(default)]
    pub resource: String,
    #[serde(default)]
    pub subresource: String,
    #[serde(default)]
    pub name: String,
    #[serde(rename = "resourceRequest", default)]
    pub resource_request: bool,
    #[serde(default)]
    pub path: String,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Endpoint {
    pub path: String,
    #[serde(default)]
    pub mappings: Vec<Mapping>,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Mapping {
    #[serde(default)]
    pub methods: Vec<String>,
    #[serde(default)]
    pub resources: Vec<Rule>,
}
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub rewrites: Rewrites,
    #[serde(rename = "resourceAttributes", default)]
    pub resource_attributes: ResourceAttributes,
}

pub fn load(path: &str) -> anyhow::Result<ConfigFile> {
    let data = std::fs::read_to_string(path)?;
    let config: ConfigFile = serde_yaml::from_str(&data)?;
    crate::authorization::validate_authorization_config(&config.authorization)?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_authorization_yaml_deserializes() {
        let config: ConfigFile = serde_yaml::from_str(
            r#"
authorization:
  rewrites:
    byQueryParameter:
      name: namespace
  resourceAttributes:
    apiVersion: v1
    resource: namespace
    subresource: metrics
    namespace: "{{ .Value }}"
  static:
    - resourceRequest: true
      resource: namespace
  endpoints:
    - path: /api/{tenant}/events
      mappings:
        - methods: [post]
          resources:
            - resourceAttributes:
                namespace: "{{ index .PathParams \"tenant\" }}"
                resource: events
"#,
        )
        .unwrap();
        let auth = config.authorization;
        assert_eq!(
            auth.rewrites.unwrap().by_query_parameter.unwrap().name,
            "namespace"
        );
        assert_eq!(auth.resource_attributes.unwrap().api_version, "v1");
        assert_eq!(auth.static_rules.len(), 1);
        assert_eq!(
            auth.endpoints[0].mappings[0].resources[0]
                .resource_attributes
                .resource,
            "events"
        );
    }

    #[test]
    fn malformed_yaml_is_rejected() {
        let result: Result<ConfigFile, _> = serde_yaml::from_str("authorization: [not-a-map]");
        assert!(result.is_err());
    }
}
