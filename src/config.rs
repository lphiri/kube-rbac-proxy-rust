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
    Ok(serde_yaml::from_str(&data)?)
}
