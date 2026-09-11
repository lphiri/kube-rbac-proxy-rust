use crate::{authn::Authenticator, authorization::Identity};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use http::Request;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use reqwest::{Certificate, Client};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct OidcAuthenticator {
    issuer: String,
    client_id: String,
    username_claim: String,
    username_prefix: String,
    groups_claim: String,
    groups_prefix: String,
    algorithms: Vec<Algorithm>,
    client: Client,
    cache: Arc<Mutex<Option<(Instant, Jwks)>>>,
}

#[derive(Clone)]
struct Jwks {
    keys: HashMap<String, DecodingKey>,
}

#[derive(Deserialize)]
struct Discovery {
    jwks_uri: String,
}

#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

impl OidcAuthenticator {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        issuer: String,
        client_id: String,
        username_claim: String,
        username_prefix: String,
        groups_claim: String,
        groups_prefix: String,
        algorithms: &[String],
        ca_file: Option<&Path>,
    ) -> Result<Self> {
        let algorithms = algorithms
            .iter()
            .map(|value| match value.as_str() {
                "RS256" => Ok(Algorithm::RS256),
                "RS384" => Ok(Algorithm::RS384),
                "RS512" => Ok(Algorithm::RS512),
                "ES256" => Ok(Algorithm::ES256),
                "ES384" => Ok(Algorithm::ES384),
                other => Err(anyhow!("unsupported OIDC signing algorithm {other}")),
            })
            .collect::<Result<Vec<_>>>()?;
        if algorithms.is_empty() {
            return Err(anyhow!("at least one OIDC signing algorithm is required"));
        }
        let mut builder = Client::builder();
        if let Some(path) = ca_file {
            builder = builder.add_root_certificate(Certificate::from_pem(&std::fs::read(path)?)?);
        }
        Ok(Self {
            issuer: issuer.trim_end_matches('/').to_string(),
            client_id,
            username_claim,
            username_prefix,
            groups_claim,
            groups_prefix,
            algorithms,
            client: builder.build()?,
            cache: Arc::new(Mutex::new(None)),
        })
    }

    async fn jwks(&self, force: bool) -> Result<Jwks> {
        if !force {
            if let Some((at, keys)) = self.cache.lock().unwrap().as_ref() {
                if at.elapsed() < Duration::from_secs(3600) {
                    return Ok(keys.clone());
                }
            }
        }
        let discovery: Discovery = self
            .client
            .get(format!("{}/.well-known/openid-configuration", self.issuer))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let set: JwkSet = self
            .client
            .get(discovery.jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;
        let keys = set
            .keys
            .into_iter()
            .filter_map(|key| {
                if key.kty != "RSA" {
                    return None;
                }
                Some((
                    key.kid?,
                    DecodingKey::from_rsa_components(&key.n?, &key.e?).ok()?,
                ))
            })
            .collect::<HashMap<_, _>>();
        let result = Jwks { keys };
        *self.cache.lock().unwrap() = Some((Instant::now(), result.clone()));
        Ok(result)
    }

    async fn authenticate_token(&self, token: &str) -> Result<Option<Identity>> {
        let header = decode_header(token).context("invalid OIDC token header")?;
        if !self.algorithms.contains(&header.alg) {
            return Ok(None);
        }
        let kid = header
            .kid
            .ok_or_else(|| anyhow!("OIDC token has no key id"))?;
        let mut keys = self.jwks(false).await?;
        if !keys.keys.contains_key(&kid) {
            keys = self.jwks(true).await?;
        }
        let Some(key) = keys.keys.get(&kid) else {
            return Ok(None);
        };
        let mut validation = Validation::new(header.alg);
        validation.set_audience(&[self.client_id.as_str()]);
        validation.set_issuer(&[self.issuer.as_str()]);
        let claims = decode::<Value>(token, key, &validation)?.claims;
        let username = claims
            .get(&self.username_claim)
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("OIDC username claim is missing or not a string"))?;
        let groups = match claims.get(&self.groups_claim) {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(|x| format!("{}{}", self.groups_prefix, x))
                .collect(),
            Some(Value::String(value)) => value
                .split_whitespace()
                .map(|x| format!("{}{}", self.groups_prefix, x))
                .collect(),
            _ => Vec::new(),
        };
        Ok(Some(Identity {
            name: format!("{}{}", self.username_prefix, username),
            groups,
        }))
    }
}

#[async_trait]
impl Authenticator for OidcAuthenticator {
    async fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>> {
        let Some(value) = request.headers().get("authorization") else {
            return Ok(None);
        };
        let Some(token) = value.to_str().ok().and_then(|x| {
            x.strip_prefix("Bearer ")
                .or_else(|| x.strip_prefix("bearer "))
        }) else {
            return Ok(None);
        };
        self.authenticate_token(token).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, EncodingKey, Header};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    // Test-only RSA key pair generated for this fixture.
    const PRIVATE: &[u8] = include_bytes!("../tests/fixtures/oidc-private.pem");
    const PUBLIC_N: &str = "ysLkHTTJRq9Tn1mWOisyFPeYVaUp_f6hVnIN3ynuCk9X2Sax6DN99hOiVcU-qqUGDa7wsQLFxTU1Pvzz1jRQXOmFSROasCno8z_tewvwM5gP-jkEGODgYkiG3mQxrVtwUZD3UO6khbMY0mhygtwaX9gHp6iWD9hj0XW-erSpC3rAFIW_24S1ij-IHYSr6SvA_h-GNEywpyexONWBw5KS8P_sWZ0RGSfERiKj2XF564JSFFvudbuQg2pKLOVzJL6qojwWXiN_jPwLGhruRVE6aV1Vc06OhlyVPYhw2_vWCSXv_S8J1xOMgN-c5pgfGesQWros97T0Gbn-1mIIxE045Q";
    const PUBLIC_E: &str = "AQAB";

    #[tokio::test]
    async fn valid_token_produces_identity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(
                    serde_json::json!({"jwks_uri": format!("{}/keys", server.uri())}),
                ),
            )
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/keys"))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                serde_json::json!({"keys":[{"kty":"RSA","kid":"test","n":PUBLIC_N,"e":PUBLIC_E}]}),
            ))
            .mount(&server)
            .await;
        let auth = OidcAuthenticator::new(
            server.uri(),
            "proxy".into(),
            "email".into(),
            "user:".into(),
            "groups".into(),
            "team:".into(),
            &["RS256".into()],
            None,
        )
        .unwrap();
        let token = encode(&Header { kid: Some("test".into()), ..Header::new(Algorithm::RS256) }, &serde_json::json!({"iss":server.uri(),"aud":"proxy","sub":"1","email":"alice","groups":["dev"],"exp":4_000_000_000u64}), &EncodingKey::from_rsa_pem(PRIVATE).unwrap()).unwrap();
        let req = Request::builder()
            .header("authorization", format!("Bearer {token}"))
            .body(())
            .unwrap();
        let identity = auth.authenticate(&req).await.unwrap().unwrap();
        assert_eq!(identity.name, "user:alice");
        assert_eq!(identity.groups, vec!["team:dev"]);
    }
}
