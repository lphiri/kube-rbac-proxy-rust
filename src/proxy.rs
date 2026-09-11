use crate::{
    authorization::{self, Identity},
    config::AuthorizationConfig,
};
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::Response,
};
use http::header::{HeaderName, HeaderValue};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use std::sync::Arc;

#[derive(Clone)]
pub struct AppState {
    pub upstream: String,
    pub authz: AuthorizationConfig,
    pub allow: Vec<String>,
    pub ignore: Vec<String>,
    pub auth_headers: bool,
    pub user_header: String,
    pub groups_header: String,
    pub group_separator: String,
    pub client: Client<HttpConnector, Body>,
}
fn matches(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "*" {
        return true;
    }
    let p: Vec<_> = pattern.split('*').collect();
    p.len() == 2 && path.starts_with(p[0]) && path.ends_with(p[1])
}
fn identity(req: &Request<Body>) -> Option<Identity> {
    let name = req
        .headers()
        .get("x-remote-user")
        .and_then(|v| v.to_str().ok())
        .filter(|x| !x.is_empty())?
        .to_string();
    let groups = req
        .headers()
        .get("x-remote-groups")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split('|')
        .filter(|x| !x.is_empty())
        .map(String::from)
        .collect();
    Some(Identity { name, groups })
}
pub async fn handler(State(state): State<Arc<AppState>>, mut req: Request<Body>) -> Response {
    let path = req.uri().path().to_string();
    if !state.allow.is_empty() && !state.allow.iter().any(|x| matches(x, &path)) {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }
    let bypass = state.ignore.iter().any(|x| matches(x, &path));
    let id = identity(&req);
    if !bypass {
        let Some(user) = id.clone() else {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        };
        let attrs_req = Request::builder()
            .method(req.method())
            .uri(req.uri())
            .body(())
            .unwrap();
        let attrs = match authorization::attributes(&state.authz, &attrs_req, user) {
            Ok(x) => x,
            Err(e) => return (StatusCode::FORBIDDEN, e.to_string()).into_response(),
        };
        if attrs.is_empty()
            || attrs
                .iter()
                .any(|a| !authorization::static_allows(&state.authz.static_rules, a))
        {
            return (StatusCode::FORBIDDEN, "Forbidden").into_response();
        }
    }
    if state.auth_headers {
        if let Some(u) = id {
            if let (Ok(uk), Ok(uv), Ok(gk), Ok(gv)) = (
                HeaderName::from_bytes(state.user_header.as_bytes()),
                HeaderValue::from_str(&u.name),
                HeaderName::from_bytes(state.groups_header.as_bytes()),
                HeaderValue::from_str(&u.groups.join(&state.group_separator)),
            ) {
                req.headers_mut().insert(uk, uv);
                req.headers_mut().insert(gk, gv);
            }
        }
    }
    let (parts, body) = req.into_parts();
    let uri = format!(
        "{}{}",
        state.upstream.trim_end_matches('/'),
        parts
            .uri
            .path_and_query()
            .map(|x| x.as_str())
            .unwrap_or("/")
    );
    let mut builder = Request::builder().method(parts.method).uri(uri);
    for (k, v) in &parts.headers {
        builder = builder.header(k, v);
    }
    match state.client.request(builder.body(body).unwrap()).await {
        Ok(r) => r.into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}
use axum::response::IntoResponse;
