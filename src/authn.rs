use crate::authorization::Identity;
use anyhow::Result;
use async_trait::async_trait;
use http::Request;
use std::sync::Arc;

#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>>;
}

#[derive(Clone, Default)]
pub struct AuthenticatorChain {
    authenticators: Arc<Vec<Arc<dyn Authenticator>>>,
}

impl AuthenticatorChain {
    pub fn new(authenticators: Vec<Arc<dyn Authenticator>>) -> Self {
        Self {
            authenticators: Arc::new(authenticators),
        }
    }
    pub async fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>> {
        for authenticator in self.authenticators.iter() {
            if let Some(identity) = authenticator.authenticate(request).await? {
                return Ok(Some(identity));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fixed(Option<Identity>);
    #[async_trait]
    impl Authenticator for Fixed {
        async fn authenticate(&self, _: &Request<()>) -> Result<Option<Identity>> {
            Ok(self.0.clone())
        }
    }
    struct Failing;
    #[async_trait]
    impl Authenticator for Failing {
        async fn authenticate(&self, _: &Request<()>) -> Result<Option<Identity>> {
            Err(anyhow::anyhow!("authentication backend failed"))
        }
    }
    fn request() -> Request<()> {
        Request::builder().uri("/metrics").body(()).unwrap()
    }
    #[tokio::test]
    async fn first_successful_authenticator_wins() {
        let c = AuthenticatorChain::new(vec![
            Arc::new(Fixed(None)),
            Arc::new(Fixed(Some(Identity {
                name: "alice".into(),
                groups: vec![],
            }))),
            Arc::new(Fixed(Some(Identity {
                name: "ignored".into(),
                groups: vec![],
            }))),
        ]);
        assert_eq!(
            c.authenticate(&request()).await.unwrap().unwrap().name,
            "alice"
        );
    }
    #[tokio::test]
    async fn empty_chain_returns_unauthenticated() {
        assert!(AuthenticatorChain::default()
            .authenticate(&request())
            .await
            .unwrap()
            .is_none());
    }
    #[tokio::test]
    async fn backend_errors_are_propagated() {
        assert!(AuthenticatorChain::new(vec![Arc::new(Failing)])
            .authenticate(&request())
            .await
            .unwrap_err()
            .to_string()
            .contains("backend failed"));
    }
}
