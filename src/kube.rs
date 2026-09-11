use crate::{
    authn::Authenticator,
    authorization::{Attributes, Identity},
};
use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use http::Request;
use reqwest::{Certificate, Client, StatusCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::Path,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[derive(Clone)]
pub struct KubernetesClient {
    inner: Arc<KubernetesClientInner>,
}
struct KubernetesClientInner {
    client: Client,
    base_url: String,
    token: String,
    token_cache: Mutex<HashMap<String, (Instant, Option<Identity>)>>,
    authz_cache: Mutex<HashMap<String, (Instant, bool)>>,
    qps: f64,
    burst: f64,
    rate: Mutex<(Instant, f64)>,
}

#[derive(Deserialize)]
struct KubeConfig {
    #[serde(rename = "current-context")]
    current_context: Option<String>,
    clusters: Vec<NamedCluster>,
    users: Vec<NamedUser>,
    contexts: Vec<NamedContext>,
}
#[derive(Deserialize)]
struct NamedCluster {
    name: String,
    cluster: Cluster,
}
#[derive(Deserialize)]
struct Cluster {
    server: String,
    #[serde(rename = "certificate-authority-data")]
    certificate_authority_data: Option<String>,
    #[serde(rename = "insecure-skip-tls-verify", default)]
    insecure_skip_tls_verify: bool,
}
#[derive(Deserialize)]
struct NamedUser {
    name: String,
    user: User,
}
#[derive(Deserialize, Default)]
struct User {
    token: Option<String>,
    #[serde(rename = "tokenFile")]
    token_file: Option<String>,
}
#[derive(Deserialize)]
struct NamedContext {
    name: String,
    context: KubeContext,
}
#[derive(Deserialize)]
struct KubeContext {
    cluster: String,
    user: String,
}

impl KubernetesClient {
    pub fn from_configuration(
        kubeconfig: Option<&Path>,
        qps: f32,
        burst: u32,
    ) -> Result<Option<Self>> {
        let (server, token, ca, insecure) = if let Some(path) = kubeconfig {
            let value: KubeConfig = serde_yaml::from_slice(
                &std::fs::read(path)
                    .with_context(|| format!("reading kubeconfig {}", path.display()))?,
            )?;
            let context_name = value
                .current_context
                .ok_or_else(|| anyhow!("kubeconfig has no current-context"))?;
            let context = value
                .contexts
                .iter()
                .find(|x| x.name == context_name)
                .ok_or_else(|| anyhow!("kubeconfig context {context_name:?} not found"))?;
            let cluster = value
                .clusters
                .iter()
                .find(|x| x.name == context.context.cluster)
                .ok_or_else(|| anyhow!("kubeconfig cluster not found"))?;
            let user = value
                .users
                .iter()
                .find(|x| x.name == context.context.user)
                .ok_or_else(|| anyhow!("kubeconfig user not found"))?;
            let token = user
                .user
                .token
                .clone()
                .or_else(|| {
                    user.user.token_file.as_ref().and_then(|p| {
                        std::fs::read_to_string(p)
                            .ok()
                            .map(|x| x.trim().to_string())
                    })
                })
                .ok_or_else(|| anyhow!("kubeconfig user has no token"))?;
            (
                cluster.cluster.server.clone(),
                token,
                cluster.cluster.certificate_authority_data.clone(),
                cluster.cluster.insecure_skip_tls_verify,
            )
        } else if let Ok(host) = std::env::var("KUBERNETES_SERVICE_HOST") {
            let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or_else(|_| "443".into());
            let token =
                std::fs::read_to_string("/var/run/secrets/kubernetes.io/serviceaccount/token")
                    .context("reading in-cluster service account token")?
                    .trim()
                    .to_string();
            let ca = std::fs::read("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")
                .ok()
                .map(|x| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, x));
            (format!("https://{host}:{port}"), token, ca, false)
        } else {
            return Ok(None);
        };
        let mut builder = Client::builder();
        if insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(encoded) = ca {
            let bytes =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)?;
            let certificate = if bytes.starts_with(b"-----BEGIN") {
                Certificate::from_pem(&bytes)?
            } else {
                Certificate::from_der(&bytes)?
            };
            builder = builder.add_root_certificate(certificate);
        }
        Ok(Some(Self {
            inner: Arc::new(KubernetesClientInner {
                client: builder.build()?,
                base_url: server.trim_end_matches('/').to_string(),
                token,
                token_cache: Mutex::new(HashMap::new()),
                authz_cache: Mutex::new(HashMap::new()),
                qps: f64::from(qps),
                burst: f64::from(burst.max(1)),
                rate: Mutex::new((Instant::now(), f64::from(burst.max(1)))),
            }),
        }))
    }
    async fn acquire(&self) {
        if self.inner.qps <= 0.0 {
            return;
        }
        loop {
            let wait = {
                let mut rate = self.inner.rate.lock().unwrap();
                let now = Instant::now();
                let elapsed = now.duration_since(rate.0).as_secs_f64();
                rate.1 = (rate.1 + elapsed * self.inner.qps).min(self.inner.burst);
                rate.0 = now;
                if rate.1 >= 1.0 {
                    rate.1 -= 1.0;
                    None
                } else {
                    Some(Duration::from_secs_f64((1.0 - rate.1) / self.inner.qps))
                }
            };
            if let Some(wait) = wait {
                tokio::time::sleep(wait).await;
            } else {
                return;
            }
        }
    }
    async fn token_review(&self, token: &str, audiences: &[String]) -> Result<Option<Identity>> {
        #[derive(Serialize)]
        struct Spec<'a> {
            token: &'a str,
            audiences: &'a [String],
        }
        #[derive(Serialize)]
        struct Review<'a> {
            #[serde(rename = "apiVersion")]
            api_version: &'static str,
            kind: &'static str,
            spec: Spec<'a>,
        }
        #[derive(Deserialize)]
        struct Status {
            authenticated: Option<bool>,
            user: Option<ReviewUser>,
        }
        #[derive(Deserialize)]
        struct ReviewUser {
            username: Option<String>,
            groups: Option<Vec<String>>,
        }
        #[derive(Deserialize)]
        struct Response {
            status: Option<Status>,
        }
        let body = Review {
            api_version: "authentication.k8s.io/v1",
            kind: "TokenReview",
            spec: Spec { token, audiences },
        };
        let response = self
            .request_with_retry(
                format!(
                    "{}/apis/authentication.k8s.io/v1/tokenreviews",
                    self.inner.base_url
                ),
                &body,
            )
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!("TokenReview returned {}", response.status()));
        }
        let result: Response = response.json().await?;
        let Some(status) = result.status else {
            return Ok(None);
        };
        if status.authenticated != Some(true) {
            return Ok(None);
        }
        let user = status.user.unwrap_or(ReviewUser {
            username: None,
            groups: None,
        });
        Ok(user.username.map(|name| Identity {
            name,
            groups: user.groups.unwrap_or_default(),
        }))
    }
    pub async fn authorize(&self, attrs: &Attributes) -> Result<bool> {
        #[derive(Serialize)]
        struct Resource<'a> {
            namespace: &'a str,
            verb: &'a str,
            group: &'a str,
            version: &'a str,
            resource: &'a str,
            subresource: &'a str,
            name: &'a str,
        }
        #[derive(Serialize)]
        struct NonResource<'a> {
            path: &'a str,
            verb: &'a str,
        }
        #[derive(Serialize)]
        struct Spec<'a> {
            user: &'a str,
            groups: &'a [String],
            #[serde(rename = "resourceAttributes", skip_serializing_if = "Option::is_none")]
            resource: Option<Resource<'a>>,
            #[serde(
                rename = "nonResourceAttributes",
                skip_serializing_if = "Option::is_none"
            )]
            non_resource: Option<NonResource<'a>>,
        }
        #[derive(Serialize)]
        struct Review<'a> {
            #[serde(rename = "apiVersion")]
            api_version: &'static str,
            kind: &'static str,
            spec: Spec<'a>,
        }
        #[derive(Deserialize)]
        struct Status {
            allowed: Option<bool>,
        }
        #[derive(Deserialize)]
        struct Response {
            status: Option<Status>,
        }
        let key = format!(
            "{}|{}|{}|{}|{}|{}|{}",
            attrs.user.name,
            attrs.verb,
            attrs.namespace,
            attrs.api_group,
            attrs.api_version,
            attrs.resource,
            attrs.path
        );
        if let Some((at, result)) = self.inner.authz_cache.lock().unwrap().get(&key) {
            if at.elapsed() < Duration::from_secs(30) {
                return Ok(*result);
            }
        }
        let resource = attrs.resource_request.then_some(Resource {
            namespace: &attrs.namespace,
            verb: &attrs.verb,
            group: &attrs.api_group,
            version: &attrs.api_version,
            resource: &attrs.resource,
            subresource: &attrs.subresource,
            name: &attrs.name,
        });
        let non_resource = (!attrs.resource_request).then_some(NonResource {
            path: &attrs.path,
            verb: &attrs.verb,
        });
        let body = Review {
            api_version: "authorization.k8s.io/v1",
            kind: "SubjectAccessReview",
            spec: Spec {
                user: &attrs.user.name,
                groups: &attrs.user.groups,
                resource,
                non_resource,
            },
        };
        let response = self
            .request_with_retry(
                format!(
                    "{}/apis/authorization.k8s.io/v1/subjectaccessreviews",
                    self.inner.base_url
                ),
                &body,
            )
            .await?;
        if !response.status().is_success() {
            return Err(anyhow!(
                "SubjectAccessReview returned {}",
                response.status()
            ));
        }
        let allowed = response
            .json::<Response>()
            .await?
            .status
            .and_then(|x| x.allowed)
            .unwrap_or(false);
        self.inner
            .authz_cache
            .lock()
            .unwrap()
            .insert(key, (Instant::now(), allowed));
        Ok(allowed)
    }

    async fn request_with_retry<T: Serialize + ?Sized>(
        &self,
        url: String,
        body: &T,
    ) -> Result<reqwest::Response> {
        for attempt in 0..3 {
            self.acquire().await;
            let response = self
                .inner
                .client
                .post(&url)
                .bearer_auth(&self.inner.token)
                .json(body)
                .send()
                .await?;
            let retryable = response.status() == StatusCode::TOO_MANY_REQUESTS
                || response.status().is_server_error();
            if !retryable || attempt == 2 {
                return Ok(response);
            }
            tokio::time::sleep(Duration::from_millis(50 * (attempt + 1))).await;
        }
        unreachable!()
    }
}

#[derive(Clone)]
pub struct KubernetesAuthenticator {
    pub client: KubernetesClient,
    pub audiences: Vec<String>,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use crate::authorization::Attributes;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn client(server: &MockServer) -> KubernetesClient {
        KubernetesClient {
            inner: Arc::new(KubernetesClientInner {
                client: Client::new(),
                base_url: server.uri(),
                token: "proxy-token".into(),
                token_cache: Mutex::new(HashMap::new()),
                authz_cache: Mutex::new(HashMap::new()),
                qps: 0.0,
                burst: 1.0,
                rate: Mutex::new((Instant::now(), 1.0)),
            }),
        }
    }

    #[tokio::test]
    async fn token_review_returns_identity() {
        let server = MockServer::start().await;
        Mock::given(method("POST")).and(path("/apis/authentication.k8s.io/v1/tokenreviews")).respond_with(ResponseTemplate::new(201).set_body_json(serde_json::json!({"status":{"authenticated":true,"user":{"username":"alice","groups":["dev"]}}}))).mount(&server).await;
        let auth = KubernetesAuthenticator {
            client: client(&server),
            audiences: vec!["proxy".into()],
        };
        let req = Request::builder()
            .header("authorization", "Bearer client-token")
            .uri("/metrics")
            .body(())
            .unwrap();
        let identity = auth.authenticate(&req).await.unwrap().unwrap();
        assert_eq!(identity.name, "alice");
        assert_eq!(identity.groups, vec!["dev"]);
    }

    #[tokio::test]
    async fn token_review_rejects_unauthenticated_tokens() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(serde_json::json!({"status":{"authenticated":false}})),
            )
            .mount(&server)
            .await;
        let auth = KubernetesAuthenticator {
            client: client(&server),
            audiences: vec![],
        };
        let req = Request::builder()
            .header("authorization", "Bearer bad-token")
            .uri("/")
            .body(())
            .unwrap();
        assert!(auth.authenticate(&req).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn subject_access_review_returns_decision() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/apis/authorization.k8s.io/v1/subjectaccessreviews"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({"status":{"allowed":true}})),
            )
            .mount(&server)
            .await;
        let attrs = Attributes {
            user: Identity {
                name: "alice".into(),
                groups: vec!["dev".into()],
            },
            verb: "get".into(),
            resource: "pods".into(),
            resource_request: true,
            ..Default::default()
        };
        assert!(client(&server).authorize(&attrs).await.unwrap());
    }

    #[tokio::test]
    async fn token_review_retries_transient_server_errors() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
            .respond_with(ResponseTemplate::new(503))
            .up_to_n_times(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path("/apis/authentication.k8s.io/v1/tokenreviews"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "status": {"authenticated": true, "user": {"username": "retry-user"}}
            })))
            .mount(&server)
            .await;
        let auth = KubernetesAuthenticator {
            client: client(&server),
            audiences: vec![],
        };
        let req = Request::builder()
            .header("authorization", "Bearer retry-token")
            .uri("/")
            .body(())
            .unwrap();
        assert_eq!(
            auth.authenticate(&req).await.unwrap().unwrap().name,
            "retry-user"
        );
    }
}
#[async_trait]
impl Authenticator for KubernetesAuthenticator {
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
        if let Some((at, result)) = self.client.inner.token_cache.lock().unwrap().get(token) {
            if at.elapsed() < Duration::from_secs(30) {
                return Ok(result.clone());
            }
        }
        let result = self.client.token_review(token, &self.audiences).await?;
        self.client
            .inner
            .token_cache
            .lock()
            .unwrap()
            .insert(token.to_string(), (Instant::now(), result.clone()));
        Ok(result)
    }
}
