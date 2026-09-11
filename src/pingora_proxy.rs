use crate::{authn::AuthenticatorChain, authorization, config::AuthorizationConfig};
use async_trait::async_trait;
use http::{Request, Uri};
use pingora::prelude::*;

#[derive(Clone)]
pub struct Proxy {
    pub upstream: Uri,
    pub authz: AuthorizationConfig,
    pub allow: Vec<String>,
    pub ignore: Vec<String>,
    pub auth_headers: bool,
    pub user_header: String,
    pub groups_header: String,
    pub group_separator: String,
    pub authenticators: AuthenticatorChain,
}
pub struct RequestContext {
    pub identity: Option<crate::authorization::Identity>,
}

fn matches(pattern: &str, path: &str) -> bool {
    if pattern == path || pattern == "*" {
        return true;
    }
    let p: Vec<_> = pattern.split('*').collect();
    p.len() == 2 && path.starts_with(p[0]) && path.ends_with(p[1])
}
fn request_from_session(session: &Session) -> Request<()> {
    Request::from_parts(session.req_header().as_owned_parts(), ())
}

#[async_trait]
impl ProxyHttp for Proxy {
    type CTX = RequestContext;
    fn new_ctx(&self) -> Self::CTX {
        RequestContext { identity: None }
    }
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let path = session.req_header().uri.path().to_string();
        if !self.allow.is_empty() && !self.allow.iter().any(|p| matches(p, &path)) {
            session.respond_error(404).await?;
            return Ok(true);
        }
        if self.ignore.iter().any(|p| matches(p, &path)) {
            return Ok(false);
        }
        let request = request_from_session(session);
        let Some(user) = self
            .authenticators
            .authenticate(&request)
            .map_err(|e| pingora::Error::explain(ErrorType::InternalError, e.to_string()))?
        else {
            session.respond_error(401).await?;
            return Ok(true);
        };
        let attrs = authorization::attributes(&self.authz, &request, user.clone())
            .map_err(|e| pingora::Error::explain(ErrorType::InternalError, e.to_string()))?;
        if attrs.is_empty()
            || attrs
                .iter()
                .any(|a| !authorization::static_allows(&self.authz.static_rules, a))
        {
            session.respond_error(403).await?;
            return Ok(true);
        }
        ctx.identity = Some(user);
        Ok(false)
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let host = self.upstream.host().ok_or_else(|| {
            pingora::Error::explain(ErrorType::InternalError, "upstream has no host")
        })?;
        let tls = self.upstream.scheme_str() == Some("https");
        let port = self
            .upstream
            .port_u16()
            .unwrap_or(if tls { 443 } else { 80 });
        Ok(Box::new(HttpPeer::new(
            format!("{host}:{port}"),
            tls,
            host.to_string(),
        )))
    }
    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if self.auth_headers {
            if let Some(user) = &ctx.identity {
                request.insert_header(self.user_header.clone(), &user.name)?;
                request.insert_header(
                    self.groups_header.clone(),
                    user.groups.join(&self.group_separator),
                )?;
            }
        }
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
pub fn build_proxy(
    upstream: Uri,
    authz: AuthorizationConfig,
    allow: Vec<String>,
    ignore: Vec<String>,
    auth_headers: bool,
    user_header: String,
    groups_header: String,
    group_separator: String,
    authenticators: AuthenticatorChain,
) -> Proxy {
    Proxy {
        upstream,
        authz,
        allow,
        ignore,
        auth_headers,
        user_header,
        groups_header,
        group_separator,
        authenticators,
    }
}
