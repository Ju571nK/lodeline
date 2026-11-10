//! The console's mint against the real `lodeline-server` in process over mutual TLS, and
//! against a scripted stand-in for the answers the server does not give on demand.

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use lodeline_fleet_api::mint::MINT_PATH;
use lodeline_proxy_api::verifier::verifier_for;
use lodeline_server::app::{build_router, AppState as ServerState};
use lodeline_server::auth::ReadToken;
use lodeline_server::config::EnrollMintConfig;
use lodeline_server::enroll::mint::MintApi;
use lodeline_server::enroll::{listener, EnrollState};
use lodeline_server::proxy::cli::cert_fingerprint;
use lodeline_server::proxy::verifiers::{Scope, VerifierEntry};
use lodeline_server::tls_accept::{load_certs, load_key, PeerCertAcceptor};
use serde_json::{json, Value};

use super::*;
use crate::fleet::{self, Client, HttpClient};
use crate::server::{router, AppState};
use crate::testutil::{pem_certs, post_files, Reply, ORIGIN, SESSION_SECRET};

const READ_TOKEN: &str = "read-bearer-SECRETREAD-0123";
const MINT_BEARER: &str = "mint-bearer-SECRETMINT-0123456789";

fn read(p: &Path) -> Vec<u8> {
    std::fs::read(p).unwrap()
}

fn roots(pki: &Pki) -> Vec<reqwest::Certificate> {
    vec![reqwest::Certificate::from_pem(&read(&pki.path("ca.crt"))).unwrap()]
}

fn identity(pki: &Pki, name: &str) -> reqwest::Identity {
    let mut pem = read(&pki.path(&format!("{name}.crt")));
    pem.push(b'\n');
    pem.extend(read(&pki.path(&format!("{name}.key"))));
    reqwest::Identity::from_pem(&pem).unwrap()
}

/// The console's own router over `enroller`.
fn console(enroller: HttpEnroller, template: Template, subjects: Vec<String>) -> Router {
    let mut st = AppState::for_tests(SESSION_SECRET, Arc::new(fleet::Mock::new(1_779_192_000)));
    let active = Active {
        template,
        enroller: Arc::new(enroller),
        public_origin: ORIGIN.into(),
        subjects,
    };
    st.enroll = Arc::new(Enroll::On(active));
    router(st)
}

fn file_template(pki: &Pki, server: &str, enroll: &str) -> Template {
    write(&pki.path("keystore.json"), &good_keystore());
    Template {
        server_url: server.into(),
        enroll_url: enroll.into(),
        ca: Source::File(FILE_CA, pki.path("ca.crt")),
        keystore: Source::File(FILE_KEYSTORE, pki.path("keystore.json")),
    }
}

// ---- the real server ---------------------------------------------------------------------

#[derive(Debug)]
struct Seen {
    path: String,
    auth: Option<String>,
    by: Option<String>,
}

#[derive(Clone)]
struct Probe {
    seen: Arc<Mutex<Vec<Seen>>>,
    cut: Arc<AtomicBool>,
    handle: axum_server::Handle,
}

/// Records each request's headers. With `cut` set, closes every connection once the mint has
/// been committed and before its answer is sent.
async fn probe(State(p): State<Probe>, req: Request, next: Next) -> Response {
    let seen = seen_of(&req);
    let path = seen.path.clone();
    p.seen.lock().unwrap().push(seen);
    let res = next.run(req).await;
    if path == MINT_PATH && p.cut.load(Ordering::SeqCst) {
        p.handle.shutdown();
        std::future::pending::<()>().await;
    }
    res
}

fn seen_of(req: &Request) -> Seen {
    let header = |n: &str| {
        let v = req.headers().get(n);
        v.and_then(|v| v.to_str().ok()).map(str::to_owned)
    };
    Seen {
        path: req.uri().path().to_owned(),
        auth: header("authorization"),
        by: header("x-lodeline-requested-by"),
    }
}

struct Fx {
    pki: Pki,
    port: u16,
    enroll_port: u16,
    probe: Probe,
}

impl Fx {
    async fn start(name: &str) -> Fx {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = Pki::new(name);
        pki.leaf("mint", "extendedKeyUsage=clientAuth\n");
        for key in ["ca.key", "server.key", "client.key", "mint.key"] {
            chmod(&pki.path(key), 0o600);
        }
        let d = pki.path("srv");
        std::fs::create_dir_all(&d).unwrap();
        let entry = VerifierEntry {
            key_id: "mint-1".into(),
            name: "console".into(),
            verifier: verifier_for(MINT_BEARER),
            scope: Scope::Enroll,
            caller_cert_fingerprint: cert_fingerprint(&pki.path("mint.crt")).unwrap(),
            not_after: None,
        };
        let entries = json!({"entries": [entry]}).to_string();
        let verifiers = write(&d.join("verifiers.json"), &entries);
        chmod(&verifiers, 0o600);
        let hosts = write(&d.join("hosts.json"), r#"{"hosts":[]}"#);
        let mut enroll = EnrollState::load(
            Some(&pki.path("ca.crt")),
            Some(&pki.path("ca.key")),
            Some(&d.join("tokens.json")),
            Some(&hosts),
            true,
            Some(30),
            d.join("enrollment-audit.jsonl"),
            None,
        )
        .expect("enrollment loads");
        let cfg = EnrollMintConfig {
            verifiers,
            ttl_seconds: None,
            max_tokens: None,
        };
        enroll.mint_api = Some(MintApi::boot(&cfg, Some(&enroll), true).unwrap());
        let st = Arc::new(ServerState {
            events_out_dir: d.clone(),
            policy_bundle_path: d.join("signed-policy.json"),
            rule_packs_bundle_path: None,
            artifacts_dir: None,
            high_water_path: d.join(".high-water.json"),
            allowlist: Default::default(),
            high_water: Default::default(),
            fleet_index: Default::default(),
            read_token: ReadToken(Some(READ_TOKEN.into())),
            active_window_days: 7,
            audit_key: lodeline_server::audit_key::AuditKey::load_or_create(&d),
            audit_head: Default::default(),
            allowlist_path: Some(hosts),
            enroll: Some(enroll),
            events_require_cert_host_match: false,
        });
        let mut ca = rustls::RootCertStore::empty();
        ca.add(pem_certs(&pki.path("ca.crt")).remove(0)).unwrap();
        let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(ca))
            .build()
            .unwrap();
        let tls = rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                load_certs(&pki.path("server.crt")).unwrap(),
                load_key(&pki.path("server.key")).unwrap(),
            )
            .unwrap();
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
        let probe = Probe {
            seen: Default::default(),
            cut: Default::default(),
            handle: axum_server::Handle::new(),
        };
        let layer = middleware::from_fn_with_state(probe.clone(), self::probe);
        let app = build_router(st.clone()).layer(layer);
        let h = probe.handle.clone();
        tokio::spawn(async move {
            let _ = axum_server::bind("127.0.0.1:0".parse().unwrap())
                .handle(h)
                .acceptor(PeerCertAcceptor::new(tls))
                .serve(app.into_make_service())
                .await;
        });
        let port = probe.handle.listening().await.expect("server binds").port();
        let sock = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let enroll_port = sock.local_addr().unwrap().port();
        let etls = listener::tls_config(&pki.path("server.crt"), &pki.path("server.key")).unwrap();
        tokio::spawn(listener::serve(sock, etls, st));
        Fx {
            pki,
            port,
            enroll_port,
            probe,
        }
    }

    fn base(&self) -> String {
        format!("https://127.0.0.1:{}", self.port)
    }

    /// The console over this server: the mint identity for the mint, the read identity for reads.
    fn console(&self, subjects: Vec<String>) -> (Router, Arc<HttpClient>) {
        let (pki, bearer) = (&self.pki, Bearer(MINT_BEARER.into()));
        let (base, timeout) = (self.base(), Duration::from_secs(10));
        let enroller =
            HttpEnroller::new(&base, bearer, identity(pki, "mint"), &roots(pki), timeout).unwrap();
        let tls = crate::config::ServerTls {
            roots: roots(pki),
            identity: Some(identity(pki, "client")),
        };
        let read = HttpClient::new(&base, READ_TOKEN, Some(&tls), Duration::from_secs(5)).unwrap();
        let listener = format!("https://127.0.0.1:{}", self.enroll_port);
        let template = file_template(pki, &base, &listener);
        (console(enroller, template, subjects), Arc::new(read))
    }

    fn audit(&self) -> Vec<Value> {
        let text = std::fs::read_to_string(self.pki.path("srv/enrollment-audit.jsonl"));
        let text = text.unwrap_or_default();
        text.lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    /// The authorization and subject headers of each mint request the server saw.
    fn mints(&self) -> Vec<(Option<String>, Option<String>)> {
        let seen = self.probe.seen.lock().unwrap();
        let mints = seen.iter().filter(|s| s.path == MINT_PATH);
        mints.map(|s| (s.auth.clone(), s.by.clone())).collect()
    }

    /// Redeems `token` on the enrollment listener the way a host does.
    async fn redeem(&self, token: &str, host_id: &str) -> u16 {
        let (key, csr) = (self.pki.path("host.key"), self.pki.path("host.csr"));
        let openssl = lodeline_server::enroll::sign::resolve_openssl().expect("openssl");
        let run = |args: &[&std::ffi::OsStr]| {
            let out = std::process::Command::new(&openssl)
                .args(args)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
        };
        let o = |s: &'static str| std::ffi::OsStr::new(s);
        run(&[
            o("genpkey"),
            o("-algorithm"),
            o("RSA"),
            o("-pkeyopt"),
            o("rsa_keygen_bits:2048"),
            o("-out"),
            key.as_os_str(),
        ]);
        let subj = format!("/CN={host_id}");
        run(&[
            o("req"),
            o("-new"),
            o("-key"),
            key.as_os_str(),
            o("-subj"),
            subj.as_ref(),
            o("-out"),
            csr.as_os_str(),
        ]);
        let c = reqwest::Client::builder()
            .use_rustls_tls()
            .add_root_certificate(roots(&self.pki).remove(0))
            .build()
            .unwrap();
        let csr_pem = std::fs::read_to_string(&csr).unwrap();
        let body = json!({"token": token, "host_id": host_id, "csr_pem": csr_pem});
        let url = format!("https://127.0.0.1:{}/v1/enroll", self.enroll_port);
        c.post(url)
            .json(&body)
            .send()
            .await
            .unwrap()
            .status()
            .as_u16()
    }
}

fn file_json(r: &Reply) -> Value {
    serde_json::from_slice(&r.body).unwrap()
}

#[tokio::test]
async fn a_signed_in_subject_gets_a_file_that_leaves_its_trace_on_both_sides() {
    let fx = Fx::start("live-ok").await;
    let (app, read_client) = fx.console(vec![]);
    let r = post_files(&app, Some("alice"), &[], "{}").await;
    assert_eq!(r.status, 200, "{}", r.text());
    let file = file_json(&r);
    let host_id = file["host_id"].as_str().unwrap();
    let token = file["token"].as_str().unwrap();
    let h = &r.headers;
    assert_eq!(h["content-type"], "application/json");
    assert_eq!(h["cache-control"], "no-store");
    let disposition = format!("attachment; filename=\"lodeline-enroll-{host_id}.json\"");
    assert_eq!(h["content-disposition"], disposition.as_str());
    assert_eq!(h["x-lodeline-enroll-host-id"], host_id);
    assert_eq!(
        h["x-lodeline-enroll-expires-at"],
        file["expires_at"].as_str().unwrap()
    );
    assert!(r.body.ends_with(b"}\n"));
    assert!(is_canonical_v4(host_id));

    // The host's own reader accepts the file at mode 0600 with no warning.
    let path = fx.pki.path("made.json");
    chmod(&write(&path, &r.text()), 0o600);
    let now = time::OffsetDateTime::now_utc();
    let parsed = lodeline_sender::enroll::file::read(&path, now).unwrap();
    assert!(parsed.warnings.is_empty(), "{:?}", parsed.warnings);
    assert_eq!(parsed.file.host_id, host_id);
    assert_eq!(parsed.file.token, token);
    assert_eq!(parsed.server_origin, fx.base());
    assert_eq!(
        parsed.enroll_origin,
        format!("https://127.0.0.1:{}", fx.enroll_port)
    );
    assert_eq!(
        parsed.file.expires_at.as_deref(),
        file["expires_at"].as_str()
    );
    assert_eq!(parsed.keys[0].id, "k1");
    let template = file_template(&fx.pki, "", "");
    assert_eq!(parsed.cas[0].sha256, template.load().unwrap().cas[0].sha256);

    // The mint carried the mint bearer and the subject. Every read carried the read token.
    let _ = read_client.get(fleet::Request::Meta).await;
    let bearer = format!("Bearer {MINT_BEARER}");
    assert_eq!(fx.mints(), [(Some(bearer), Some("alice".into()))]);
    {
        let seen = fx.probe.seen.lock().unwrap();
        let reads: Vec<_> = seen.iter().filter(|s| s.path != MINT_PATH).collect();
        assert!(!reads.is_empty());
        for s in reads {
            assert_eq!(
                s.auth.as_deref(),
                Some(format!("Bearer {READ_TOKEN}").as_str()),
                "{s:?}"
            );
        }
    }

    // The server's signed chain has the mint with the asserted subject, then the issue.
    assert_eq!(fx.redeem(token, host_id).await, 200);
    let lines = fx.audit();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["decision"], "token_minted");
    assert_eq!(lines[0]["host_id"], host_id);
    assert_eq!(lines[0]["requested_by_asserted"], "alice");
    assert_eq!(lines[0]["management_key_id"], "mint-1");
    assert_eq!(lines[1]["decision"], "issued");
    assert_eq!(fx.redeem(token, host_id).await, 403);
}

#[tokio::test]
async fn the_servers_two_conflicts_come_back_as_the_consoles_own_answers() {
    let fx = Fx::start("live-conflict").await;
    let (app, _) = fx.console(vec![]);
    let host = new_host_id().unwrap();
    let body = json!({"host_id": host}).to_string();
    let first = post_files(&app, Some("alice"), &[], &body).await;
    assert_eq!(first.status, 200);
    let token = file_json(&first)["token"].as_str().unwrap().to_owned();
    let second = post_files(&app, Some("alice"), &[], &body).await;
    assert_eq!(
        (second.status, second.code().as_str()),
        (409, "token_outstanding")
    );
    assert!(second.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("enroll-token"));
    assert_eq!(fx.redeem(&token, &host).await, 200);
    let third = post_files(&app, Some("alice"), &[], &body).await;
    assert_eq!((third.status, third.code().as_str()), (409, "host_exists"));
    assert_eq!(fx.mints().len(), 3);
    for r in [&second, &third] {
        assert!(!r.text().contains(MINT_BEARER) && !r.text().contains(&token));
    }
}

#[tokio::test]
async fn a_subject_with_odd_characters_still_gets_a_file_and_the_header_is_visible_ascii() {
    let fx = Fx::start("live-odd").await;
    let (app, _) = fx.console(vec![]);
    let subjects = [
        "Zo\u{eb} \u{1f980}",
        "line\nbreak\ttab\r\u{7f}\u{1b}[31m",
        "quote\"back\\slash'",
    ];
    for who in subjects {
        let r = post_files(&app, Some(who), &[], "{}").await;
        assert_eq!(r.status, 200, "{who:?}: {}", r.text());
    }
    let seen = fx.mints();
    assert_eq!(seen.len(), 3);
    for ((_, by), who) in seen.iter().zip(subjects) {
        let by = by.as_deref().unwrap();
        assert!(by.bytes().all(|b| (0x20..=0x7e).contains(&b)), "{by:?}");
        assert_eq!(by, who.escape_default().to_string());
    }
}

#[tokio::test]
async fn a_connection_dropped_after_the_token_was_committed_gives_502_no_file_and_no_retry() {
    let fx = Fx::start("live-drop").await;
    let (app, _) = fx.console(vec![]);
    fx.probe.cut.store(true, Ordering::SeqCst);
    let host = new_host_id().unwrap();
    let body = json!({"host_id": host}).to_string();
    let r = post_files(&app, Some("alice"), &[], &body).await;
    assert_eq!((r.status, r.code().as_str()), (502, "enroll_failed"));
    assert!(r.headers.get("content-disposition").is_none());
    assert_eq!(fx.mints().len(), 1, "the console did not retry");
    let tokens = std::fs::read_to_string(fx.pki.path("srv/tokens.json")).unwrap();
    assert!(
        tokens.contains(&host),
        "the server committed one token that nobody holds"
    );
}

// ---- a scripted stand-in --------------------------------------------------------------------

#[derive(Clone)]
enum Say {
    Json(u16, Value),
    Raw(u16, &'static str),
    Redirect,
    Hang,
}

type Hits = Arc<Mutex<Vec<(String, Option<String>)>>>;

struct Stub {
    base: String,
    hits: Hits,
    pki: Pki,
}

static NEXT: AtomicUsize = AtomicUsize::new(0);
const BODY_MARK: &str = "SECRETMARK-STUBBODY";
const ANSWERED: &str = "tok-0123456789";
const HOST: &str = "00000000-0000-4000-8000-000000000000";

async fn stub(say: Say) -> Stub {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let pki = Pki::new(&format!("stub-{}", NEXT.fetch_add(1, Ordering::SeqCst)));
    let tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            load_certs(&pki.path("server.crt")).unwrap(),
            load_key(&pki.path("server.key")).unwrap(),
        )
        .unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let base = format!("https://{}", listener.local_addr().unwrap());
    let hits: Hits = Default::default();
    let (h, target) = (hits.clone(), format!("{base}/target"));
    let app = Router::new().fallback(move |req: Request| {
        let (h, say, target) = (h.clone(), say.clone(), target.clone());
        async move {
            let auth = req.headers().get("authorization");
            let auth = auth.and_then(|v| v.to_str().ok()).map(str::to_owned);
            h.lock().unwrap().push((req.uri().path().to_owned(), auth));
            let code = |s: u16| axum::http::StatusCode::from_u16(s).unwrap();
            match say {
                Say::Json(s, body) => (code(s), axum::Json(body)).into_response(),
                Say::Raw(s, body) => (code(s), body).into_response(),
                Say::Redirect => (code(307), [("location", target)]).into_response(),
                Say::Hang => {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    code(200).into_response()
                }
            }
        }
    });
    let config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(tls));
    tokio::spawn(async move {
        let server = axum_server::from_tcp_rustls(listener, config);
        let _ = server.serve(app.into_make_service()).await;
    });
    Stub { base, hits, pki }
}

/// The console asking the stand-in, with a short timeout.
async fn ask(say: Say, body: &str) -> (Reply, Stub) {
    let stub = stub(say).await;
    let (pki, bearer) = (&stub.pki, Bearer(MINT_BEARER.into()));
    let timeout = Duration::from_millis(400);
    let enroller = HttpEnroller::new(
        &stub.base,
        bearer,
        identity(pki, "client"),
        &roots(pki),
        timeout,
    )
    .unwrap();
    let app = console(enroller, Template::mock(), vec![]);
    (post_files(&app, Some("alice"), &[], body).await, stub)
}

fn ok_answer(host: &str) -> Value {
    json!({"expires_at": "2030-01-01T00:00:00Z", "host_id": host, "token": ANSWERED})
}

#[tokio::test]
async fn every_answer_of_the_server_maps_to_one_code_and_is_asked_once() {
    let bad = |code: &str| json!({"error": {"code": code, "message": BODY_MARK}});
    let cases: Vec<(Say, u16, &str)> = vec![
        (Say::Json(409, bad("host_exists")), 409, "host_exists"),
        (
            Say::Json(409, bad("token_outstanding")),
            409,
            "token_outstanding",
        ),
        (Say::Json(409, bad("something_new")), 502, "enroll_failed"),
        (Say::Raw(409, "not json"), 502, "enroll_failed"),
        (
            Say::Json(429, bad("too_many_tokens")),
            429,
            "enrollment_limit_reached",
        ),
        (Say::Raw(404, BODY_MARK), 502, "enroll_unavailable"),
        (Say::Json(401, bad("unauthorized")), 502, "enroll_refused"),
        (Say::Json(403, bad("forbidden")), 502, "enroll_refused"),
        (Say::Json(422, bad("invalid_host_id")), 502, "enroll_failed"),
        (Say::Json(500, bad("internal")), 502, "enroll_failed"),
        (Say::Json(503, bad("audit")), 502, "enroll_failed"),
        (Say::Json(200, ok_answer("x")), 502, "enroll_failed"),
        (Say::Raw(201, "{"), 502, "enroll_failed"),
        (Say::Raw(201, "{\"host_id\":\"x\"}"), 502, "enroll_failed"),
        (Say::Json(201, ok_answer(HOST)), 502, "enroll_failed"),
        (Say::Redirect, 502, "enroll_failed"),
        (Say::Hang, 502, "enroll_failed"),
    ];
    for (i, (say, status, code)) in cases.into_iter().enumerate() {
        // The last-but-two case answers a host id other than the one asked for.
        let body = if i == 14 {
            r#"{"host_id":"11111111-1111-4111-8111-111111111111"}"#
        } else {
            "{}"
        };
        let (r, stub) = ask(say, body).await;
        assert_eq!(
            (r.status, r.code().as_str()),
            (status, code),
            "case {i}: {}",
            r.text()
        );
        assert!(r.headers.get("content-disposition").is_none(), "case {i}");
        for secret in [BODY_MARK, MINT_BEARER, ANSWERED] {
            assert!(!r.text().contains(secret), "case {i}: {}", r.text());
        }
        let hits = stub.hits.lock().unwrap();
        assert_eq!(hits.len(), 1, "case {i}: asked once, got {hits:?}");
        assert_eq!(
            hits[0].1.as_deref(),
            Some(format!("Bearer {MINT_BEARER}").as_str())
        );
    }
}

#[tokio::test]
async fn a_redirect_is_an_error_and_the_bearer_does_not_reach_its_target() {
    let (r, stub) = ask(Say::Redirect, "{}").await;
    assert_eq!(r.code(), "enroll_failed");
    let hits = stub.hits.lock().unwrap();
    assert!(hits.iter().all(|(path, _)| path == MINT_PATH), "{hits:?}");
}

#[tokio::test]
async fn an_answer_with_an_unusable_token_or_time_is_not_made_into_a_file() {
    let long = "t".repeat(257);
    for (what, token, expires) in [
        ("whitespace", "tok with space", "2030-01-01T00:00:00Z"),
        ("empty", "", "2030-01-01T00:00:00Z"),
        ("long", long.as_str(), "2030-01-01T00:00:00Z"),
        ("time", ANSWERED, "tomorrow"),
    ] {
        let answer = json!({"expires_at": expires, "host_id": HOST, "token": token});
        let (r, _) = ask(
            Say::Json(201, answer),
            &json!({"host_id": HOST}).to_string(),
        )
        .await;
        assert_eq!(r.code(), "enroll_failed", "{what}: {}", r.text());
    }
    let (ok, _) = ask(
        Say::Json(201, ok_answer(HOST)),
        &json!({"host_id": HOST}).to_string(),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.text());
}

#[tokio::test]
async fn the_enroller_and_the_servers_answer_never_print_the_token() {
    let stub = stub(Say::Raw(200, "")).await;
    let (pki, bearer) = (&stub.pki, Bearer(MINT_BEARER.into()));
    let timeout = Duration::from_secs(1);
    let enroller = HttpEnroller::new(
        &stub.base,
        bearer,
        identity(pki, "client"),
        &roots(pki),
        timeout,
    )
    .unwrap();
    let answer = lodeline_fleet_api::mint::MintResponse {
        expires_at: "e".into(),
        host_id: "h".into(),
        token: TOKEN.into(),
    };
    for shown in [
        format!("{enroller:?}"),
        format!("{answer:?}"),
        format!("{answer:#?}"),
    ] {
        assert!(
            !shown.contains(MARK) && !shown.contains("SECRETMINT"),
            "{shown}"
        );
    }
}
