#![cfg(feature = "validation")]

//! Generated provider actions, exercised only against loopback HTTP mocks.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{Arc, Mutex, OnceLock},
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use kingfisher_rules::{Confidence, Rule, Rules, get_builtin_rules};
use kingfisher_scanner::validation::{Revoker, revocation::RevocationIndeterminate};
use serde_json::{Value, json};

type Vars = BTreeMap<String, String>;

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    uri: String,
    headers: HeaderMap,
    body: Vec<u8>,
}

#[derive(Default)]
struct MockState {
    requests: Vec<Recorded>,
    replies: VecDeque<(u16, Value)>,
}

struct Server {
    url: String,
    state: Arc<Mutex<MockState>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn new(replies: Vec<(u16, Value)>) -> Self {
        async fn handle(State(state): State<Arc<Mutex<MockState>>>, req: Request) -> Response {
            let (parts, body) = req.into_parts();
            let body = to_bytes(body, 1024 * 1024).await.unwrap();
            let mut state = state.lock().unwrap();
            state.requests.push(Recorded {
                method: parts.method.to_string(),
                uri: parts.uri.to_string(),
                headers: parts.headers,
                body: body.to_vec(),
            });
            let (status, body) = state.replies.pop_front().unwrap_or((500, json!({})));
            Response::builder()
                .status(StatusCode::from_u16(status).unwrap())
                .header("Content-Type", "application/json")
                .body(if status == 204 { Body::empty() } else { Body::from(body.to_string()) })
                .unwrap()
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(MockState { requests: vec![], replies: replies.into() }));
        let app = Router::new().fallback(handle).with_state(Arc::clone(&state));
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { url, state, task }
    }

    fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }
}

fn vars(pairs: &[(&str, &str)]) -> Vars {
    pairs.iter().map(|(k, v)| ((*k).into(), (*v).into())).collect()
}

fn builtin(id: &str, server: &Server) -> Rule {
    static RULES: OnceLock<Rules> = OnceLock::new();
    let rules = RULES.get_or_init(|| get_builtin_rules(Some(Confidence::Low)).unwrap());
    let mut syntax = rules.rules[&format!("betterleaks.{id}")].clone();
    // Retain the generated AST/action and all matchers; replace only literal vendor origins.
    // There is no production endpoint override or ambient environment dependency.
    fn localize(value: &mut Value, url: &str) {
        match value {
            Value::String(text) => {
                for origin in [
                    "https://api.notion.com",
                    "https://api.resend.com",
                    "https://iam.twilio.com",
                    "https://api.openai.com",
                    "https://api.anthropic.com",
                    "https://api.vercel.com",
                    "https://api.github.com",
                    "https://apikeys.googleapis.com",
                    "https://huggingface.co",
                    "https://slack.com",
                ] {
                    *text = text.replace(origin, url);
                }
            }
            Value::Array(values) => values.iter_mut().for_each(|v| localize(v, url)),
            Value::Object(values) => values.values_mut().for_each(|v| localize(v, url)),
            _ => {}
        }
    }
    let mut action =
        serde_json::to_value(syntax.revocation.as_ref().expect("built-in action")).unwrap();
    localize(&mut action, &server.url);
    syntax.revocation = Some(serde_json::from_value(action).unwrap());
    Rule::new(syntax)
}

fn revoker() -> Revoker {
    Revoker::new().unwrap().timeout(Duration::from_secs(5)).unwrap()
}

struct OwnerCase {
    rule: &'static str,
    secret: &'static str,
    vars: Vars,
    value_var: &'static str,
    id_var: &'static str,
    method: &'static str,
    path: &'static str,
    response: Value,
}

fn owner_cases() -> Vec<OwnerCase> {
    vec![
        OwnerCase {
            rule: "resend-api-key.1",
            secret: "re_fixture_candidate",
            vars: vars(&[
                ("RESEND_ADMIN_API_KEY", "resend-owner-fixture"),
                ("RESEND_API_KEY_ID", "12345678-1234-1234-1234-123456789abc"),
                ("RESEND_API_KEY_VALUE", "re_fixture_candidate"),
            ]),
            value_var: "RESEND_API_KEY_VALUE",
            id_var: "RESEND_API_KEY_ID",
            method: "DELETE",
            path: "/api-keys/12345678-1234-1234-1234-123456789abc",
            response: json!({"object":"api_key","id":"12345678-1234-1234-1234-123456789abc","deleted":true}),
        },
        OwnerCase {
            rule: "openai-api-key",
            secret: "sk-svcacct-fixture",
            vars: vars(&[
                ("OPENAI_ADMIN_KEY", "openai-owner-fixture"),
                ("OPENAI_PROJECT_ID", "proj_fixture"),
                ("OPENAI_API_KEY_ID", "key_fixture"),
                ("OPENAI_API_KEY_VALUE", "sk-svcacct-fixture"),
            ]),
            value_var: "OPENAI_API_KEY_VALUE",
            id_var: "OPENAI_API_KEY_ID",
            method: "DELETE",
            path: "/v1/organization/projects/proj_fixture/api_keys/key_fixture",
            response: json!({"object":"organization.project.api_key.deleted","id":"key_fixture","deleted":true}),
        },
        OwnerCase {
            rule: "anthropic-api-key",
            secret: "sk-ant-fixture",
            vars: vars(&[
                ("ANTHROPIC_ADMIN_KEY", "anthropic-owner-fixture"),
                ("ANTHROPIC_API_KEY_ID", "apikey_fixture"),
                ("ANTHROPIC_API_KEY_VALUE", "sk-ant-fixture"),
            ]),
            value_var: "ANTHROPIC_API_KEY_VALUE",
            id_var: "ANTHROPIC_API_KEY_ID",
            method: "POST",
            path: "/v1/organizations/api_keys/apikey_fixture",
            response: json!({"type":"api_key","id":"apikey_fixture","status":"inactive"}),
        },
        OwnerCase {
            rule: "vercel-ai-gateway-key",
            secret: "vck_fixture",
            vars: vars(&[
                ("VERCEL_OWNER_TOKEN", "vercel-owner-fixture"),
                ("VERCEL_TEAM_ID", "team_fixture"),
                ("VERCEL_AI_GATEWAY_KEY_ID", "gateway_key_fixture"),
                ("VERCEL_AI_GATEWAY_KEY_VALUE", "vck_fixture"),
            ]),
            value_var: "VERCEL_AI_GATEWAY_KEY_VALUE",
            id_var: "VERCEL_AI_GATEWAY_KEY_ID",
            method: "DELETE",
            path: "/v1/api-keys/gateway_key_fixture?teamId=team_fixture",
            response: Value::Null,
        },
    ]
}

#[tokio::test]
async fn owner_id_flows_use_exact_scoped_targets_and_separate_authentication() {
    for case in owner_cases() {
        let status = if case.rule == "vercel-ai-gateway-key" { 204 } else { 200 };
        let server = Server::new(vec![(status, case.response)]).await;
        let result =
            revoker().revoke(&builtin(case.rule, &server), case.secret, &case.vars).await.unwrap();
        assert!(result.revoked, "{}", case.rule);
        let requests = server.requests();
        assert_eq!(requests.len(), 1, "{}", case.rule);
        let req = &requests[0];
        assert_eq!(req.method, case.method);
        assert_eq!(req.uri, case.path);
        assert!(!String::from_utf8_lossy(&req.body).contains(case.secret));
        let expected_auth = match case.rule {
            "resend-api-key.1" => "Bearer resend-owner-fixture",
            "openai-api-key" => "Bearer openai-owner-fixture",
            "vercel-ai-gateway-key" => "Bearer vercel-owner-fixture",
            _ => {
                assert_eq!(req.headers["x-api-key"], "anthropic-owner-fixture");
                assert_eq!(req.headers["anthropic-version"], "2023-06-01");
                assert_eq!(
                    serde_json::from_slice::<Value>(&req.body).unwrap(),
                    json!({"status":"inactive"})
                );
                assert!(!req.headers.contains_key("authorization"));
                continue;
            }
        };
        assert_eq!(req.headers["authorization"], expected_auth);
        assert!(req.body.is_empty());
    }
}

#[tokio::test]
async fn missing_owner_inputs_unrelated_findings_and_path_injection_never_mutate() {
    for case in owner_cases() {
        let server = Server::new(vec![]).await;
        let rule = builtin(case.rule, &server);
        for key in case.vars.keys() {
            let mut missing = case.vars.clone();
            missing.remove(key);
            assert!(revoker().revoke(&rule, case.secret, &missing).await.is_err(), "{key}");
        }
        let mut unrelated = case.vars.clone();
        unrelated.insert(case.value_var.into(), "a-different-token".into());
        assert!(!revoker().revoke(&rule, case.secret, &unrelated).await.unwrap().revoked);
        assert!(!revoker().revoke(&rule, "another-finding", &case.vars).await.unwrap().revoked);
        let mut traversal = case.vars.clone();
        traversal.insert(case.id_var.into(), "../other-key?all=true".into());
        assert!(!revoker().revoke(&rule, case.secret, &traversal).await.unwrap().revoked);
        let mut empty = case.vars.clone();
        empty.insert(case.value_var.into(), String::new());
        assert!(revoker().revoke(&rule, "", &empty).await.is_err());
        assert!(server.requests().is_empty(), "{}", case.rule);
    }
}

#[tokio::test]
async fn owner_mutations_do_not_retry_or_accept_generic_success() {
    for case in owner_cases() {
        for (status, body) in
            [(202, json!({})), (429, json!({})), (503, json!({})), (200, json!({"ok":true}))]
        {
            let server = Server::new(vec![(status, body)]).await;
            let error = revoker()
                .revoke(&builtin(case.rule, &server), case.secret, &case.vars)
                .await
                .unwrap_err();
            assert!(
                error.downcast_ref::<RevocationIndeterminate>().is_some(),
                "{}: {error:#}",
                case.rule
            );
            assert_eq!(server.requests().len(), 1, "{}: HTTP {status}", case.rule);
        }
    }
}

#[tokio::test]
async fn exact_json_evidence_is_required_even_with_http_200() {
    for case in owner_cases().into_iter().filter(|c| c.rule != "vercel-ai-gateway-key") {
        for field in [
            "id",
            if case.rule == "anthropic-api-key" { "type" } else { "object" },
            if case.rule == "anthropic-api-key" { "status" } else { "deleted" },
        ] {
            let mut body = case.response.clone();
            body.as_object_mut().unwrap().remove(field);
            let server = Server::new(vec![(200, body)]).await;
            assert!(
                revoker()
                    .revoke(&builtin(case.rule, &server), case.secret, &case.vars)
                    .await
                    .is_err(),
                "{}: {field}",
                case.rule
            );
            assert_eq!(server.requests().len(), 1);
        }
        let mut body = case.response;
        body["id"] = json!("different_key");
        let server = Server::new(vec![(200, body)]).await;
        assert!(
            revoker().revoke(&builtin(case.rule, &server), case.secret, &case.vars).await.is_err()
        );
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn openai_admin_branch_needs_no_project_and_never_deletes_an_account() {
    let server = Server::new(vec![(200, json!({"object":"organization.admin_api_key.deleted","id":"key_admin_fixture","deleted":true}))]).await;
    let inputs = vars(&[
        ("OPENAI_ADMIN_KEY", "separate-admin-fixture"),
        ("OPENAI_API_KEY_ID", "key_admin_fixture"),
        ("OPENAI_API_KEY_VALUE", "sk-admin-candidate"),
    ]);
    assert!(
        revoker()
            .revoke(&builtin("openai-api-key", &server), "sk-admin-candidate", &inputs)
            .await
            .unwrap()
            .revoked
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(requests[0].uri, "/v1/organization/admin_api_keys/key_admin_fixture");
    assert_eq!(requests[0].headers["authorization"], "Bearer separate-admin-fixture");
}

fn notion_inputs() -> Vars {
    vars(&[("NOTION_CLIENT_ID", "fixture-client"), ("NOTION_CLIENT_SECRET", "fixture-secret")])
}

#[tokio::test]
async fn notion_requires_app_owned_active_oauth_and_confirms_inactive_after_revoke() {
    let server = Server::new(vec![
        (200, json!({"active":true})),
        (200, json!({})),
        (200, json!({"active":false})),
    ])
    .await;
    let token = "ntn_fixture_oauth";
    assert!(
        revoker()
            .revoke(&builtin("notion-api-token", &server), token, &notion_inputs())
            .await
            .unwrap()
            .revoked
    );
    let requests = server.requests();
    assert_eq!(
        requests.iter().map(|r| r.uri.as_str()).collect::<Vec<_>>(),
        ["/v1/oauth/introspect", "/v1/oauth/revoke", "/v1/oauth/introspect"]
    );
    for req in requests {
        assert_eq!(req.method, "POST");
        assert_eq!(req.headers["authorization"], "Basic Zml4dHVyZS1jbGllbnQ6Zml4dHVyZS1zZWNyZXQ=");
        assert_eq!(req.headers["notion-version"], "2026-03-11");
        assert_eq!(req.headers["content-type"], "application/json");
        assert_eq!(serde_json::from_slice::<Value>(&req.body).unwrap(), json!({"token":token}));
    }
}

#[tokio::test]
async fn notion_rejects_inactive_or_unauthorized_tokens_and_never_repeats_revocation() {
    for (replies, expected_requests) in [
        (vec![(200, json!({"active":false}))], 1),
        (vec![(401, json!({}))], 1),
        (vec![(200, json!({"active":true})), (202, json!({}))], 2),
        (vec![(200, json!({"active":true})), (200, json!({})), (200, json!({"active":true}))], 3),
        (vec![(200, json!({"active":true})), (200, json!({})), (503, json!({}))], 3),
    ] {
        let server = Server::new(replies).await;
        assert!(
            !revoker()
                .revoke(&builtin("notion-api-token", &server), "ntn_fixture", &notion_inputs())
                .await
                .is_ok_and(|result| result.revoked)
        );
        let requests = server.requests();
        assert_eq!(requests.len(), expected_requests);
        assert!(requests.iter().filter(|r| r.uri == "/v1/oauth/revoke").count() <= 1);
    }
    let server = Server::new(vec![]).await;
    assert!(
        revoker()
            .revoke(&builtin("notion-api-token", &server), "ntn_fixture", &Vars::new())
            .await
            .is_err()
    );
    assert!(server.requests().is_empty());
}

const GCP_NAME: &str = "projects/12345/locations/global/keys/key_fixture";
const GCP_OPERATION: &str = "operations/delete_fixture";

fn gcp_done() -> Value {
    json!({"name":GCP_OPERATION,"done":true,"response":{"name":GCP_NAME,"deleteTime":"2026-01-01T00:00:00Z"}})
}

#[tokio::test]
async fn gcp_deletes_only_the_lookup_resource_and_confirms_completed_operation() {
    for immediately_done in [true, false] {
        let mut replies = vec![
            (200, json!({"name":GCP_NAME})),
            (200, if immediately_done { gcp_done() } else { json!({"name":GCP_OPERATION}) }),
        ];
        if !immediately_done {
            replies.push((200, gcp_done()));
        }
        let server = Server::new(replies).await;
        let token = "gcp-fixture+/?&other=key";
        assert!(
            revoker()
                .revoke(
                    &builtin("gcp-api-key", &server),
                    token,
                    &vars(&[("GCP_ACCESS_TOKEN", "gcp-owner-fixture")])
                )
                .await
                .unwrap()
                .revoked
        );
        let requests = server.requests();
        assert_eq!(requests.len(), if immediately_done { 2 } else { 3 });
        assert_eq!(requests[0].method, "GET");
        let url = reqwest::Url::parse(&format!("{}{}", server.url, requests[0].uri)).unwrap();
        assert_eq!(url.path(), "/v2/keys:lookupKey");
        assert_eq!(url.query_pairs().collect::<Vec<_>>(), [("keyString".into(), token.into())]);
        assert_eq!(requests[1].method, "DELETE");
        assert_eq!(requests[1].uri, format!("/v2/{GCP_NAME}"));
        if !immediately_done {
            assert_eq!(requests[2].method, "GET");
            assert_eq!(requests[2].uri, format!("/v2/{GCP_OPERATION}"));
        }
        for req in requests {
            assert_eq!(req.headers["authorization"], "Bearer gcp-owner-fixture");
            assert!(req.body.is_empty());
        }
    }
}

#[tokio::test]
async fn gcp_pending_error_and_wrong_resource_are_unknown_without_resubmission() {
    for final_body in [
        json!({"name":GCP_OPERATION,"done":false}),
        json!({"name":GCP_OPERATION,"done":true,"error":{"code":7}}),
        json!({"name":GCP_OPERATION,"done":true,"response":{"name":"projects/12345/locations/global/keys/unrelated"}}),
        json!({"name":GCP_OPERATION,"done":true}),
    ] {
        let server = Server::new(vec![
            (200, json!({"name":GCP_NAME})),
            (200, json!({"name":GCP_OPERATION})),
            (200, final_body),
        ])
        .await;
        let error = revoker()
            .revoke(
                &builtin("gcp-api-key", &server),
                "gcp-fixture",
                &vars(&[("GCP_ACCESS_TOKEN", "owner")]),
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<RevocationIndeterminate>().is_some(), "{error:#}");
        let requests = server.requests();
        assert_eq!(requests.len(), 3);
        assert_eq!(requests.iter().filter(|r| r.method == "DELETE").count(), 1);
    }
}

#[tokio::test]
async fn gcp_missing_auth_or_unsafe_lookup_names_never_delete() {
    let server = Server::new(vec![]).await;
    assert!(
        revoker()
            .revoke(&builtin("gcp-api-key", &server), "gcp-fixture", &Vars::new())
            .await
            .is_err()
    );
    assert!(server.requests().is_empty());
    for name in [
        "",
        "../projects/12345",
        "projects/12345/locations/global/keys/a?all=true",
        "https://other.invalid/key",
    ] {
        let server = Server::new(vec![(200, json!({"name":name}))]).await;
        assert!(
            !revoker()
                .revoke(
                    &builtin("gcp-api-key", &server),
                    "gcp-fixture",
                    &vars(&[("GCP_ACCESS_TOKEN", "owner")])
                )
                .await
                .unwrap()
                .revoked
        );
        assert_eq!(server.requests().len(), 1);
    }
}

#[tokio::test]
async fn gcp_invalid_operation_does_not_construct_an_untrusted_poll_url() {
    for operation in
        ["operations/../../other?x=y", "operations/.", "operations/..", "https://other.invalid/op"]
    {
        let server =
            Server::new(vec![(200, json!({"name":GCP_NAME})), (200, json!({"name":operation}))])
                .await;
        let error = revoker()
            .revoke(
                &builtin("gcp-api-key", &server),
                "gcp-fixture",
                &vars(&[("GCP_ACCESS_TOKEN", "owner")]),
            )
            .await
            .unwrap_err();
        assert!(error.downcast_ref::<RevocationIndeterminate>().is_some());
        assert_eq!(server.requests().len(), 2);
    }
}

#[tokio::test]
async fn github_user_report_is_unauthenticated_and_accepted_is_indeterminate() {
    let token = format!("ghu_{}", "a".repeat(36));
    let server = Server::new(vec![(202, json!({}))]).await;
    let error = revoker()
        .revoke(&builtin("github-app-token", &server), &token, &Vars::new())
        .await
        .unwrap_err();
    assert!(error.downcast_ref::<RevocationIndeterminate>().is_some());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].uri, "/credentials/revoke");
    assert_eq!(requests[0].method, "POST");
    assert!(!requests[0].headers.contains_key("authorization"));
    assert_eq!(requests[0].headers["x-github-api-version"], "2026-03-10");
    assert_eq!(
        serde_json::from_slice::<Value>(&requests[0].body).unwrap(),
        json!({"credentials":[token]})
    );
}

#[tokio::test]
async fn github_installation_tokens_are_not_reported_to_an_unsupported_endpoint() {
    let server = Server::new(vec![]).await;
    let token = format!("ghs_{}", "a".repeat(36));
    assert!(
        !revoker()
            .revoke(&builtin("github-app-token", &server), &token, &Vars::new())
            .await
            .unwrap()
            .revoked
    );
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn twilio_deletes_only_the_sid_with_account_credentials_and_requires_204() {
    for status in [204, 200, 202, 429, 503] {
        let server = Server::new(vec![(status, json!({}))]).await;
        let token = format!("SK{}", "a".repeat(32));
        let inputs =
            vars(&[("TWILIO_ACCOUNT_SID", "ACfixture"), ("TWILIO_AUTH_TOKEN", "auth-fixture")]);
        let result = revoker().revoke(&builtin("twilio-api-key", &server), &token, &inputs).await;
        if status == 204 {
            assert!(result.unwrap().revoked);
        } else {
            assert!(result.unwrap_err().downcast_ref::<RevocationIndeterminate>().is_some());
        }
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, "DELETE");
        assert_eq!(requests[0].uri, format!("/v1/Keys/{token}"));
        assert_eq!(requests[0].headers["authorization"], "Basic QUNmaXh0dXJlOmF1dGgtZml4dHVyZQ==");
        assert!(requests[0].body.is_empty());
    }
}

#[tokio::test]
async fn twilio_missing_credentials_or_malformed_sid_never_delete() {
    let server = Server::new(vec![]).await;
    let rule = builtin("twilio-api-key", &server);
    let inputs =
        vars(&[("TWILIO_ACCOUNT_SID", "ACfixture"), ("TWILIO_AUTH_TOKEN", "auth-fixture")]);
    for sid in ["..", "SK../other", "SK1234"] {
        assert!(!revoker().revoke(&rule, sid, &inputs).await.unwrap().revoked);
    }
    assert!(revoker().revoke(&rule, "", &inputs).await.is_err());
    let sid = format!("SK{}", "a".repeat(32));
    for key in inputs.keys() {
        let mut missing = inputs.clone();
        missing.remove(key);
        assert!(revoker().revoke(&rule, &sid, &missing).await.is_err());
    }
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn existing_huggingface_github_and_slack_primary_actions_keep_their_behavior() {
    for (id, response, path) in [
        ("huggingface-access-token", (202, json!({})), "/api/credentials/revoke"),
        ("huggingface-organization-api-token", (202, json!({})), "/api/credentials/revoke"),
        ("github-pat", (202, json!({})), "/credentials/revoke"),
        ("slack-user-token", (200, json!({"ok":true,"revoked":true})), "/api/auth.revoke"),
    ] {
        let server = Server::new(vec![response]).await;
        let inputs = vars(&[("GITHUB_API_BASE_URL", &server.url)]);
        assert!(
            revoker()
                .revoke(&builtin(id, &server), "fixture-legacy-token", &inputs)
                .await
                .unwrap()
                .revoked,
            "{id}"
        );
        let requests = server.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].uri, path);
    }
}
