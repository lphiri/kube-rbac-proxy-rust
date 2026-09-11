use http::Request;
use kube_rbac_proxy::{authorization, config::AuthorizationConfig, Identity};

#[test]
fn configured_static_authorization_matches_authenticated_request() {
    let config: AuthorizationConfig = serde_yaml::from_str(
        r#"
static:
  - user:
      name: alice
    verb: get
    resourceRequest: true
    resource: pods
    namespace: team-a
resourceAttributes:
  resourceRequest: true
  resource: pods
  namespace: team-a
"#,
    )
    .unwrap();
    let request = Request::builder()
        .method("GET")
        .uri("/apis/v1/namespaces/team-a/pods")
        .body(())
        .unwrap();
    let attrs = authorization::attributes(
        &config,
        &request,
        Identity {
            name: "alice".into(),
            groups: vec![],
        },
    )
    .unwrap();
    assert_eq!(attrs.len(), 1);
    assert!(authorization::static_allows(
        &config.static_rules,
        &attrs[0]
    ));
}
