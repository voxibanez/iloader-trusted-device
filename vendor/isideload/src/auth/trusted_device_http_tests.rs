//! Exercise the real challenge/verification HTTP methods against loopback.
//! No Apple account, Apple endpoint or live anisette server is used.
use super::*;
use crate::anisette::{AnisetteClientInfo, AnisetteDataResponse, AnisetteProvider};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::sync::RwLock;

struct MockAnisette;

#[async_trait::async_trait]
impl AnisetteProvider for MockAnisette {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        Ok(AnisetteDataResponse::Data(AnisetteData::for_auth_test()))
    }

    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        Ok(AnisetteClientInfo {
            client_info: "test".into(),
            user_agent: "test".into(),
        })
    }

    async fn provision(&mut self, _gs: &Arc<GrandSlam>, _force: bool) -> Result<(), Report> {
        bail!("mock anisette must not provision")
    }
}

#[derive(Debug, PartialEq, Eq)]
struct RecordedRequest {
    request_line: String,
    security_code: Option<String>,
}

struct MockServer {
    url: String,
    requests: Arc<Mutex<Vec<RecordedRequest>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl MockServer {
    fn new(replies: Vec<(u16, String)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let worker = thread::spawn(move || {
            for (status, body) in replies {
                let mut stream = loop {
                    if worker_stop.load(Ordering::Relaxed) {
                        return;
                    }
                    match listener.accept() {
                        Ok((stream, _)) => break stream,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                        }
                        Err(error) => panic!("mock HTTP accept: {error}"),
                    }
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut buffer = [0_u8; 1024];
                    let count = stream.read(&mut buffer).unwrap();
                    assert!(count > 0, "incomplete mock HTTP request");
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 16_384, "unexpectedly large HTTP headers");
                }
                let request = String::from_utf8(request).unwrap();
                recorded.lock().unwrap().push(RecordedRequest {
                    request_line: request.lines().next().unwrap().into(),
                    security_code: request.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("security-code")
                            .then(|| value.trim().to_owned())
                    }),
                });
                let response = format!(
                    "HTTP/1.1 {status} Test\r\nContent-Type: text/xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });
        Self {
            url,
            requests,
            stop,
            worker: Some(worker),
        }
    }

    fn account(&self) -> AppleAccount {
        let mut urls = Dictionary::new();
        urls.insert(
            "trustedDeviceSecondaryAuth".into(),
            plist::Value::String(format!("{}/device-code", self.url)),
        );
        urls.insert(
            "validateCode".into(),
            plist::Value::String(format!("{}/validate-code", self.url)),
        );
        AppleAccount {
            email: "test@example.invalid".into(),
            spd: Some(plist!(dict { "adsid": "test", "GsIdmsToken": "test" })),
            anisette_generator: AnisetteDataGenerator::new(Arc::new(RwLock::new(MockAnisette))),
            grandslam_client: Arc::new(GrandSlam::for_auth_test(urls)),
            trusted_phone_numbers: None,
            login_state: LoginState::NeedsDevice2FA,
            last_login_status: LoginStatusSummary::default(),
            debug: false,
            last_error: None,
            err_429_retries: None,
        }
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn reply_xml(reply: &Dictionary) -> String {
    let mut bytes = Vec::new();
    plist::to_writer_xml(&mut bytes, reply).unwrap();
    String::from_utf8(bytes).unwrap()
}

fn verification_reply(error_code: i64) -> String {
    reply_xml(&plist!(dict {
        "Status": { "ec": error_code, "em": "test verification status" }
    }))
}

#[test]
fn successful_trusted_device_flow_requests_and_validates_a_real_code() {
    let server = MockServer::new(vec![(200, String::new()), (200, verification_reply(0))]);
    runtime().block_on(async {
        let mut account = server.account();
        account.send_trusted_device_2fa().await.unwrap();
        assert_eq!(
            account
                .verify_trusted_device_2fa("123456".into())
                .await
                .unwrap(),
            LoginState::NeedsLogin
        );
    });
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![
            RecordedRequest {
                request_line: "GET /device-code HTTP/1.1".into(),
                security_code: None
            },
            RecordedRequest {
                request_line: "GET /validate-code HTTP/1.1".into(),
                security_code: Some("123456".into())
            },
        ]
    );
}

#[test]
fn device_http_403_fails_without_falling_back_to_sms() {
    let server = MockServer::new(vec![(403, "Forbidden".into())]);
    runtime().block_on(async {
        let error = server
            .account()
            .send_trusted_device_2fa()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("HTTP 403"));
        assert!(error.to_string().contains("no SMS was requested"));
    });
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![RecordedRequest {
            request_line: "GET /device-code HTTP/1.1".into(),
            security_code: None
        },]
    );
}

#[test]
fn rejected_device_code_remains_unverified() {
    let server = MockServer::new(vec![(200, verification_reply(-21669))]);
    runtime().block_on(async {
        let mut account = server.account();
        assert_eq!(
            account
                .verify_trusted_device_2fa("000000".into())
                .await
                .unwrap(),
            LoginState::NeedsDevice2FAVerification
        );
        assert!(account.last_error.as_ref().unwrap().contains("-21669"));
    });
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![RecordedRequest {
            request_line: "GET /validate-code HTTP/1.1".into(),
            security_code: Some("000000".into())
        },]
    );
}

#[test]
fn explicit_verification_success_supports_integer_string_and_grandslam_envelopes() {
    // AltSign reads the top-level ec as NSNumber or NSString. GrandSlam-style
    // replies may instead carry it in Status or Response/Status.
    let replies = [
        plist!(dict { "ec": 0_i64 }),
        plist!(dict { "ec": "0" }),
        plist!(dict { "Status": { "ec": 0_i64 } }),
        plist!(dict { "Response": { "ec": "0" } }),
        plist!(dict { "Response": { "Status": { "ec": 0_i64, "hsc": 200_i64 } } }),
    ];
    for reply in replies {
        let server = MockServer::new(vec![(200, reply_xml(&reply))]);
        runtime().block_on(async {
            let mut account = server.account();
            assert_eq!(
                account
                    .verify_trusted_device_2fa("123456".into())
                    .await
                    .unwrap(),
                LoginState::NeedsLogin
            );
            assert!(account.last_error.is_none());
        });
        assert_eq!(server.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn nested_and_string_error_codes_never_become_verification_success() {
    let replies = [
        plist!(dict { "ec": "-21669" }),
        plist!(dict { "Response": { "Status": { "ec": -21669_i64 } } }),
        // A superficial success must not hide an error in the response body.
        plist!(dict { "ec": 0_i64, "Response": { "Status": { "ec": "-21669" } } }),
    ];
    for reply in replies {
        let server = MockServer::new(vec![(200, reply_xml(&reply))]);
        runtime().block_on(async {
            let mut account = server.account();
            assert_eq!(
                account
                    .verify_trusted_device_2fa("000000".into())
                    .await
                    .unwrap(),
                LoginState::NeedsDevice2FAVerification
            );
            assert!(account.last_error.as_ref().unwrap().contains("-21669"));
        });
    }
}

#[test]
fn malformed_or_missing_verification_status_fails_closed_without_response_secrets() {
    let replies = [
        Dictionary::new(),
        plist!(dict { "hsc": 200_i64 }),
        plist!(dict { "ec": false }),
        plist!(dict { "ec": "not-a-number" }),
        plist!(dict { "ec": 0_i64, "Status": "private-envelope" }),
        plist!(dict { "Response": { "Status": { "em": "private-message" } } }),
        plist!(dict { "ec": 0_i64, "Response": { "Status": { "ec": false } } }),
        plist!(dict { "ec": 0_i64, "Status": { "hsc": 403_i64 } }),
        plist!(dict { "ec": -21669_i64, "Status": { "ec": -12345_i64 } }),
    ];
    for reply in replies {
        let server = MockServer::new(vec![(200, reply_xml(&reply))]);
        runtime().block_on(async {
            let mut account = server.account();
            let error = account
                .verify_trusted_device_2fa("000000".into())
                .await
                .expect_err("an explicit successful verification status is required");
            assert!(account.last_error.is_none());
            assert!(!format!("{error:?}").contains("private"));
        });
    }
}

#[test]
fn an_auto_pushed_code_is_validated_without_requesting_another_challenge() {
    let server = MockServer::new(vec![(200, verification_reply(-21669))]);
    let callbacks = AtomicUsize::new(0);
    runtime().block_on(async {
        let mut account = server.account();
        let status = plist!(dict { "hsc": 409_i64, "ec": 0_i64 });
        account.login_state = login_state_from_status(&status).unwrap();
        account.last_login_status = LoginStatusSummary::from_status(&status);
        let error = account
            .complete_login("unused-test-password", |params: TwoFactorCallbackParams| {
                assert!(!params.sms);
                assert!(!params.unknown);
                assert!(params.numbers.is_empty());
                assert!(params.selected_number_id.is_none());
                let response = match callbacks.fetch_add(1, Ordering::Relaxed) {
                    0 => TwoFactorCallbackResponse::SubmitCode("000000".into()),
                    1 => {
                        assert!(params.last_error.as_ref().unwrap().contains("-21669"));
                        TwoFactorCallbackResponse::Abort
                    }
                    _ => panic!("unexpected repeated verification callback"),
                };
                async move { Ok(response) }
            })
            .await
            .unwrap_err();
        assert!(error.to_string().contains("authentication canceled"));
    });
    assert_eq!(callbacks.load(Ordering::Relaxed), 2);
    assert_eq!(
        *server.requests.lock().unwrap(),
        vec![RecordedRequest {
            request_line: "GET /validate-code HTTP/1.1".into(),
            security_code: Some("000000".into()),
        }]
    );
}
