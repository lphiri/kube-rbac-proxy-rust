use crate::authorization::Identity;
use anyhow::Result;
use http::Request;
use std::sync::Arc;

pub trait Authenticator: Send + Sync {
    fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>>;
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
    pub fn authenticate(&self, request: &Request<()>) -> Result<Option<Identity>> {
        for authenticator in self.authenticators.iter() {
            if let Some(identity) = authenticator.authenticate(request)? {
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
    impl Authenticator for Fixed {
        fn authenticate(&self, _: &Request<()>) -> Result<Option<Identity>> {
            Ok(self.0.clone())
        }
    }
    struct Failing;
    impl Authenticator for Failing {
        fn authenticate(&self, _: &Request<()>) -> Result<Option<Identity>> {
            Err(anyhow::anyhow!("authentication backend failed"))
        }
    }
    fn request() -> Request<()> {
        Request::builder().uri("/metrics").body(()).unwrap()
    }
    #[test]
    fn first_successful_authenticator_wins() {
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
        assert_eq!(c.authenticate(&request()).unwrap().unwrap().name, "alice");
    }
    #[test]
    fn empty_chain_returns_unauthenticated() {
        assert!(AuthenticatorChain::default()
            .authenticate(&request())
            .unwrap()
            .is_none());
    }
    #[test]
    fn backend_errors_are_propagated() {
        assert!(AuthenticatorChain::new(vec![Arc::new(Failing)])
            .authenticate(&request())
            .unwrap_err()
            .to_string()
            .contains("backend failed"));
    }
}
