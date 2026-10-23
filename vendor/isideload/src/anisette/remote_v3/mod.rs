mod state;
mod websocket;

use std::sync::Arc;
use web_time::SystemTime;

use base64::prelude::*;
use plist_macro::plist;
use reqwest::{
    ClientBuilder,
    header::{CONTENT_TYPE, HeaderMap, HeaderValue},
};
use reqwest_middleware::ClientBuilder as MwClientBuilder;
use rootcause::option_ext::OptionExt;
use rootcause::prelude::*;
use serde::Deserialize;
use tokio::sync::OnceCell;
use tracing::{debug, info, warn};

use crate::anisette::remote_v3::websocket::AppWebSocket;
use crate::anisette::{AnisetteClientInfo, AnisetteData, AnisetteProvider};
use crate::anisette::{
    AnisetteDataResponse,
    remote_v3::{state::AnisetteState, websocket::WsMessage},
};
use crate::auth::grandslam::GrandSlam;
use crate::util::plist::PlistDataExtract;
use crate::util::storage::{SideloadingStorage, new_storage};

pub const DEFAULT_ANISETTE_V3_URL: &str = "https://ani.jkcoxson.com";
pub const ANISETTE_STATE_KEY: &str = "anisette_state";
// A separate key makes the current-Mac transition provision once without
// deleting the identity used by earlier builds. Subsequent sign-ins reuse it.
pub const ANISETTE_MAC_STATE_KEY: &str = "anisette_state_current_mac_v1";

// AnisetteKit defaults, also used by SideInstaller 1.6.1's 2026-10-23 fix:
// https://github.com/mahee96/AnisetteKit/blob/db8b41022697b6c19be8a5f01a1ce834145a2a26/Sources/Constants.swift
const CURRENT_MAC_CLIENT_INFO: &str =
    "<MacBookPro18,3> <macOS;26.6;25F84> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";
const CURRENT_MAC_USER_AGENT: &str = "AuthKit/1 (Macintosh; OS X 26.6) (com.apple.akd/1.0)";

fn mac_version(client: &str) -> Option<(u32, u32)> {
    let rest = ["<macOS;", "<Mac OS X;"]
        .iter()
        .find_map(|marker| client.split_once(marker).map(|(_, rest)| rest))?;
    let version = rest.split([';', '>']).next()?.trim();
    let mut parts = version.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().unwrap_or("0").parse().ok()?;
    Some((major, minor))
}

fn effective_client_info(advertised: AnisetteClientInfo) -> AnisetteClientInfo {
    if mac_version(&advertised.client_info).is_some_and(|version| version < (10, 13)) {
        info!("Using current Mac authentication identity for a legacy Mac anisette server");
        return AnisetteClientInfo {
            client_info: CURRENT_MAC_CLIENT_INFO.to_string(),
            user_agent: CURRENT_MAC_USER_AGENT.to_string(),
        };
    }
    advertised
}

fn state_key_for(client_info: &AnisetteClientInfo) -> &'static str {
    if mac_version(&client_info.client_info).is_some_and(|version| version >= (10, 13)) {
        ANISETTE_MAC_STATE_KEY
    } else {
        ANISETTE_STATE_KEY
    }
}

pub struct RemoteV3AnisetteProvider {
    pub state: Option<AnisetteState>,
    url: String,
    storage: Box<dyn SideloadingStorage>,
    serial_number: String,
    client: reqwest_middleware::ClientWithMiddleware,
    websocket_proxy: Option<String>,
    client_info: OnceCell<AnisetteClientInfo>,
}

impl RemoteV3AnisetteProvider {
    /// Create a new RemoteV3AnisetteProvider with the given URL and config path
    ///
    /// # Arguments
    /// - `url`: The URL of the remote anisette service
    /// - `storage`: The storage backend for anisette data
    /// - `serial_number`: The serial number of the device
    pub fn new(
        url: &str,
        storage: Box<dyn SideloadingStorage>,
        serial_number: String,
    ) -> Result<Self, Report> {
        Ok(Self {
            state: None,
            url: url.to_string(),
            storage,
            serial_number,
            client: Self::build_reqwest_client(None)?,
            websocket_proxy: None,
            client_info: OnceCell::new(),
        })
    }

    pub fn set_websocket_proxy(mut self, websocket_proxy: Option<String>) -> Result<Self, Report> {
        self.websocket_proxy = websocket_proxy;
        self.client = Self::build_reqwest_client(self.websocket_proxy.clone())?;
        Ok(self)
    }

    fn build_reqwest_client(
        websocket_proxy: Option<String>,
    ) -> Result<reqwest_middleware::ClientWithMiddleware, Report> {
        if let Some(websocket_proxy) = websocket_proxy {
            use crate::auth::middleware::WasmProxyMiddleware;

            let client = ClientBuilder::new().build()?;

            Ok(MwClientBuilder::new(client)
                .with(WasmProxyMiddleware::new(websocket_proxy))
                .build())
        } else {
            let client = ClientBuilder::new().build()?;

            Ok(MwClientBuilder::new(client).build())
        }
    }

    pub fn default() -> Result<Self, Report> {
        Self::new(
            DEFAULT_ANISETTE_V3_URL,
            Box::new(new_storage()),
            "0".to_string(),
        )
    }

    pub fn set_url(mut self, url: &str) -> RemoteV3AnisetteProvider {
        self.url = url.to_string();
        self.client_info = OnceCell::new();
        self.state = None;
        self
    }

    pub fn set_storage(mut self, storage: Box<dyn SideloadingStorage>) -> RemoteV3AnisetteProvider {
        self.storage = storage;
        self.state = None;
        self
    }

    pub fn set_serial_number(mut self, serial_number: String) -> RemoteV3AnisetteProvider {
        self.serial_number = serial_number;
        self
    }
}

#[cfg_attr(feature = "wasm", async_trait::async_trait(?Send))]
#[cfg_attr(not(feature = "wasm"), async_trait::async_trait)]
impl AnisetteProvider for RemoteV3AnisetteProvider {
    async fn get_anisette_data(&self) -> Result<AnisetteDataResponse, Report> {
        self.fetch_headers(None).await
    }

    async fn resync(&self, sim: &str) -> Result<AnisetteDataResponse, Report> {
        self.fetch_headers(Some(sim)).await
    }

    // Cache the effective profile for this provider. Provisioning, SRP, and
    // verification must not change identities if server metadata changes.
    async fn get_client_info(&self) -> Result<AnisetteClientInfo, Report> {
        let info = self
            .client_info
            .get_or_try_init(|| async {
                let advertised = self
                    .client
                    .get(format!("{}/v3/client_info", self.url))
                    .send()
                    .await
                    .context("Failed to request /v3/client_info from anisette server")?
                    .error_for_status()
                    .context("anisette server returned an error for /v3/client_info")?
                    .json::<AnisetteClientInfo>()
                    .await
                    .context("Failed to parse /v3/client_info response")?;
                Ok::<_, Report>(effective_client_info(advertised))
            })
            .await?;
        Ok(info.clone())
    }

    async fn provision(&mut self, gs: &Arc<GrandSlam>, force_reset: bool) -> Result<(), Report> {
        self.get_client_info().await?;
        self.get_state(gs, force_reset).await?;
        Ok(())
    }
}

impl RemoteV3AnisetteProvider {
    async fn fetch_headers(&self, sim: Option<&str>) -> Result<AnisetteDataResponse, Report> {
        let Some(state) = self.state.as_ref() else {
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        };

        let Some(adi_pb) = state.adi_pb.as_ref() else {
            return Ok(AnisetteDataResponse::NeedsProvisioning);
        };

        let client_info = self.get_client_info().await?;

        let mut body = serde_json::json!({
            "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
            "adi_pb": BASE64_STANDARD.encode(adi_pb),
        });
        if let Some(sim) = sim {
            body["sim"] = serde_json::Value::String(sim.to_string());
            body["device_id"] = serde_json::Value::String(state.get_device_id());
            body["md_lu"] = serde_json::Value::String(hex::encode(state.get_md_lu()));
        }

        let headers = self
            .client
            .post(format!("{}/v3/get_headers", self.url))
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await?
            .error_for_status()?
            .json::<AnisetteHeaders>()
            .await?;

        match headers {
            AnisetteHeaders::Headers {
                machine_id,
                one_time_password,
                routing_info,
            } => Ok(AnisetteDataResponse::Data(AnisetteData {
                machine_id,
                one_time_password,
                routing_info,
                _device_description: client_info.client_info.clone(),
                device_unique_identifier: state.get_device_id(),
                _local_user_id: hex::encode(state.get_md_lu()),
                generated_at: SystemTime::now(),
            })),
            AnisetteHeaders::GetHeadersError { message } => {
                if message.contains("-45061") {
                    warn!("Server says anisette not provisioned");
                    return Ok(AnisetteDataResponse::IncorrectlyProvisioned);
                }
                Err(report!("Failed to get anisette headers").attach(message))
            }
        }
    }

    async fn get_state(
        &mut self,
        gs: &Arc<GrandSlam>,
        force_reset: bool,
    ) -> Result<&mut AnisetteState, Report> {
        let state_key = state_key_for(&gs.client_info);
        if force_reset {
            warn!("Resetting anisette state");
            self.state = Some(AnisetteState::new());
        } else if self.state.is_none() {
            if let Ok(Some(state)) = &self.storage.retrieve_data(state_key) {
                if let Ok(state) = plist::from_bytes(state) {
                    info!("Loaded existing anisette state");
                    self.state = Some(state);
                } else {
                    warn!("Failed to parse existing anisette state, starting fresh");
                    self.state = Some(AnisetteState::new());
                }
            } else {
                info!("No existing anisette state found for this client profile");
                self.state = Some(AnisetteState::new());
            }
        }

        let state = self.state.as_mut().ok_or_report()?;
        if !state.is_provisioned() {
            info!("Provisioning required...");
            Self::provision(state, gs, &self.url, self.websocket_proxy.as_deref())
                .await
                .context("Failed to provision")?;
        }
        let buf = Vec::new();
        let mut writer = std::io::BufWriter::new(buf);
        plist::to_writer_xml(&mut writer, &state)?;
        self.storage.store_data(state_key, &writer.into_inner()?)?;

        Ok(state)
    }

    async fn provisioning_headers(state: &AnisetteState) -> Result<HeaderMap, Report> {
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-Apple-I-MD-LU",
            HeaderValue::from_str(&hex::encode(state.get_md_lu()))?,
        );
        // headers.insert(
        //     "X-Apple-I-Client-Time",
        //     HeaderValue::from_str(
        //         &Utc::now()
        //             .round_subsecs(0)
        //             .format("%+")
        //             .to_string()
        //             .replace("+00:00", "Z"),
        //     )?,
        // );
        // headers.insert("X-Apple-I-TimeZone", HeaderValue::from_static("UTC"));
        // headers.insert("X-Apple-Locale", HeaderValue::from_static("en_US"));
        headers.insert(
            "X-Mme-Device-Id",
            HeaderValue::from_str(&state.get_device_id())?,
        );

        Ok(headers)
    }
    async fn provision(
        state: &mut AnisetteState,
        gs: &Arc<GrandSlam>,
        url: &str,
        proxy_url: Option<&str>,
    ) -> Result<(), Report> {
        let start_provisioning = gs.get_url("midStartProvisioning")?;
        let end_provisioning = gs.get_url("midFinishProvisioning")?;

        let websocket_url = format!("{}/v3/provisioning_session", url)
            .replace("https://", "wss://")
            .replace("http://", "ws://");

        debug!("Starting provisioning at {}", websocket_url);
        // let (mut ws_stream, _) = timeout(
        //     Duration::from_secs(30),
        //     tokio_tungstenite::connect_async(&websocket_url),
        // )
        // .await
        // .map_err(|_| {
        //     report!("Timed out connecting to provisioning socket. Try a different anisette server.")
        // })
        // .context("Failed to connect to provisioning socket")?
        // .context("Failed to connect to provisioning socket")?;

        let mut ws = AppWebSocket::connect(&websocket_url, proxy_url.as_deref())
            .await
            .context("Failed to connect to provisioning socket")?;

        debug!("Connected to provisioning socket");

        loop {
            let Some(msg) = ws.next().await else { continue };
            let msg = msg?;

            let text = match msg {
                WsMessage::Close => bail!("Provisioning socket closed unexpectedly"),
                WsMessage::Text(t) => t,
            };

            debug!("Received provisioning message: {}", text);
            let provision_msg: ProvisioningMessage = serde_json::from_str(&text)?;

            match provision_msg {
                ProvisioningMessage::GiveIdentifier => {
                    ws.send_text(
                        serde_json::json!({
                            "identifier": BASE64_STANDARD.encode(state.keychain_identifier),
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send identifier")?;
                }
                ProvisioningMessage::GiveStartProvisioningData => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {}
                    });

                    let response = gs
                        .plist_request(
                            &start_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                            None,
                        )
                        .await
                        .context("Failed to send start provisioning request")?;

                    let spim = response
                        .get_str("spim")
                        .context("Start provisioning response missing spim")?;

                    ws.send_text(
                        serde_json::json!({
                            "spim": spim,
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send start provisioning data")?;
                }
                ProvisioningMessage::GiveEndProvisioningData { cpim } => {
                    let body = plist!(dict {
                        "Header": {},
                        "Request": {
                            "cpim": cpim,
                        }
                    });

                    let response = gs
                        .plist_request(
                            &end_provisioning,
                            &body,
                            Some(Self::provisioning_headers(state).await?),
                            None,
                        )
                        .await
                        .context("Failed to send end provisioning request")?;

                    ws.send_text(
                        serde_json::json!({
                            "ptm": response
                                .get_str("ptm")
                                .context("End provisioning response missing ptm")?,
                            "tk": response
                                .get_str("tk")
                                .context("End provisioning response missing tk")?,
                        })
                        .to_string()
                        .into(),
                    )
                    .await
                    .context("Failed to send start provisioning data")?;
                }
                ProvisioningMessage::ProvisioningSuccess { adi_pb } => {
                    state.adi_pb = Some(BASE64_STANDARD.decode(adi_pb)?);
                    ws.close().await?;
                    info!("Provisioning successful");
                    break;
                }
                ProvisioningMessage::Timeout => bail!("Anisette provisioning timed out"),
                ProvisioningMessage::InvalidIdentifier => {
                    bail!("Anisette provisioning failed: invalid identifier")
                }
                ProvisioningMessage::StartProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: start provisioning error")
                            .attach(message),
                    );
                }
                ProvisioningMessage::EndProvisioningError { message } => {
                    return Err(
                        report!("Anisette provisioning failed: end provisioning error")
                            .attach(message),
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum ProvisioningMessage {
    GiveIdentifier,
    GiveStartProvisioningData,
    GiveEndProvisioningData { cpim: String },
    ProvisioningSuccess { adi_pb: String },
    Timeout,
    InvalidIdentifier,
    StartProvisioningError { message: String },
    EndProvisioningError { message: String },
}

#[derive(Deserialize)]
#[serde(tag = "result")]
enum AnisetteHeaders {
    GetHeadersError {
        message: String,
    },
    Headers {
        #[serde(rename = "X-Apple-I-MD-M")]
        machine_id: String,
        #[serde(rename = "X-Apple-I-MD")]
        one_time_password: String,
        #[serde(rename = "X-Apple-I-MD-RINFO")]
        routing_info: String,
    },
}

#[cfg(all(test, not(feature = "wasm")))]
mod current_mac_tests {
    use super::*;
    use crate::util::storage::InMemoryStorage;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;
    use std::time::{Duration, Instant};

    const OLD_MAC: &str =
        "<MacBookPro13,3> <Mac OS X;10.12.6;16G29> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

    #[derive(Clone, Default)]
    struct SharedStorage(Arc<InMemoryStorage>);

    impl SideloadingStorage for SharedStorage {
        fn store(&self, key: &str, value: &str) -> Result<(), Report> {
            self.0.store(key, value)
        }

        fn retrieve(&self, key: &str) -> Result<Option<String>, Report> {
            self.0.retrieve(key)
        }

        fn delete(&self, key: &str) -> Result<(), Report> {
            self.0.delete(key)
        }
    }

    fn profile(client_info: &str, user_agent: &str) -> AnisetteClientInfo {
        AnisetteClientInfo {
            client_info: client_info.into(),
            user_agent: user_agent.into(),
        }
    }

    fn provider(url: &str, storage: SharedStorage) -> RemoteV3AnisetteProvider {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut provider =
            RemoteV3AnisetteProvider::new(url, Box::new(storage), "0".into()).unwrap();
        provider.client = MwClientBuilder::new(
            reqwest::Client::builder()
                .no_proxy()
                .timeout(Duration::from_secs(2))
                .build()
                .unwrap(),
        )
        .build();
        provider
    }

    fn provisioned_fixture() -> AnisetteState {
        AnisetteState {
            keychain_identifier: [17; 16],
            adi_pb: Some(vec![1, 2, 3]),
        }
    }

    #[test]
    fn legacy_mac_metadata_gets_current_mac_identity_and_separate_storage() {
        for old in [OLD_MAC, "<MacBookPro11,1> <macOS;10.9.5;13F1911> <akd>"] {
            let actual = effective_client_info(profile(old, "old-user-agent"));
            assert_eq!(actual.client_info, CURRENT_MAC_CLIENT_INFO);
            assert_eq!(actual.user_agent, CURRENT_MAC_USER_AGENT);
            assert_eq!(state_key_for(&actual), ANISETTE_MAC_STATE_KEY);
        }
    }

    #[test]
    fn modern_and_non_mac_server_metadata_remains_unchanged() {
        for (client, key) in [
            (
                "<MacBookPro14,1> <Mac OS X;10.13.6;17G66> <akd>",
                ANISETTE_MAC_STATE_KEY,
            ),
            ("<Mac14,2> <macOS;15;24A335> <akd>", ANISETTE_MAC_STATE_KEY),
            ("<PC> <Windows;6.2(0,0);9200> <iTunes>", ANISETTE_STATE_KEY),
            ("<Pixel 7> <Android;14;UQ1A> <akd>", ANISETTE_STATE_KEY),
            ("<Mac> <macOS;unknown;build> <akd>", ANISETTE_STATE_KEY),
        ] {
            let actual = effective_client_info(profile(client, "server-user-agent"));
            assert_eq!(actual.client_info, client);
            assert_eq!(actual.user_agent, "server-user-agent");
            assert_eq!(state_key_for(&actual), key);
        }
    }

    #[tokio::test]
    async fn metadata_is_fetched_once_and_survives_the_server_closing() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let body = serde_json::json!({
            "client_info": OLD_MAC,
            "user_agent": "old-user-agent"
        })
        .to_string();
        // Serve exactly one request, then drop the listener. A second fetch
        // (including a concurrent cache miss) cannot accidentally succeed.
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "metadata request did not arrive");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("metadata mock accept failed: {error}"),
                }
            };
            // macOS can preserve the listener's nonblocking mode on accept.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0; 1024];
            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).unwrap();
                assert!(read > 0 && request.len() < 8192, "invalid mock request");
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).unwrap();
            drop(stream);
            String::from_utf8(request).unwrap()
        });
        let provider = provider(&url, SharedStorage::default());
        let (first, simultaneous) =
            tokio::join!(provider.get_client_info(), provider.get_client_info());
        let request = server.join().unwrap();
        assert!(request.starts_with("GET /v3/client_info HTTP/1.1\r\n"));
        for actual in [
            first.unwrap(),
            simultaneous.unwrap(),
            provider.get_client_info().await.unwrap(),
        ] {
            assert_eq!(actual.client_info, CURRENT_MAC_CLIENT_INFO);
            assert_eq!(actual.user_agent, CURRENT_MAC_USER_AGENT);
        }
    }

    #[tokio::test]
    async fn current_mac_migration_preserves_legacy_and_reuses_new_identity() {
        let storage = SharedStorage::default();
        let mut legacy_bytes = Vec::new();
        plist::to_writer_xml(&mut legacy_bytes, &provisioned_fixture()).unwrap();
        storage
            .store_data(ANISETTE_STATE_KEY, &legacy_bytes)
            .unwrap();
        let mut first = provider("http://127.0.0.1:1", storage.clone());
        let mut gs = GrandSlam::for_auth_test(plist::Dictionary::new());
        gs.client_info = profile(CURRENT_MAC_CLIENT_INFO, CURRENT_MAC_USER_AGENT);
        let gs = Arc::new(gs);

        // An empty URL bag fails before provisioning can touch the network.
        // Success here would mean the already-provisioned legacy state leaked in.
        let error = first.get_state(&gs, false).await.unwrap_err();
        assert!(format!("{error:?}").contains("URL bag"));
        assert!(first.state.as_ref().unwrap().adi_pb.is_none());
        assert_eq!(
            storage.retrieve_data(ANISETTE_STATE_KEY).unwrap(),
            Some(legacy_bytes.clone())
        );
        assert!(
            storage
                .retrieve_data(ANISETTE_MAC_STATE_KEY)
                .unwrap()
                .is_none()
        );

        // Simulate successful provisioning, then exercise the real persistence
        // path. A fresh provider must reuse it without needing a URL bag.
        first.state.as_mut().unwrap().adi_pb = Some(vec![4, 5, 6]);
        let identifier = first
            .get_state(&gs, false)
            .await
            .unwrap()
            .keychain_identifier;
        let stored = storage
            .retrieve_data(ANISETTE_MAC_STATE_KEY)
            .unwrap()
            .unwrap();
        let saved: AnisetteState = plist::from_bytes(&stored).unwrap();
        assert_eq!(saved.keychain_identifier, identifier);
        assert_eq!(saved.adi_pb, Some(vec![4, 5, 6]));
        drop(first);

        let mut next = provider("http://127.0.0.1:1", storage.clone());
        let reused = next.get_state(&gs, false).await.unwrap();
        assert_eq!(reused.keychain_identifier, identifier);
        assert_eq!(reused.adi_pb, Some(vec![4, 5, 6]));
        assert_eq!(
            storage.retrieve_data(ANISETTE_STATE_KEY).unwrap(),
            Some(legacy_bytes)
        );
        assert_eq!(
            storage.retrieve_data(ANISETTE_MAC_STATE_KEY).unwrap(),
            Some(stored)
        );
    }

    #[test]
    fn changing_url_or_storage_discards_state_from_the_previous_configuration() {
        let mut configured = provider("http://127.0.0.1:1", SharedStorage::default());
        configured
            .client_info
            .set(profile(CURRENT_MAC_CLIENT_INFO, CURRENT_MAC_USER_AGENT))
            .unwrap();
        configured.state = Some(provisioned_fixture());
        let mut changed = configured.set_url("http://127.0.0.1:2");
        assert_eq!(changed.url, "http://127.0.0.1:2");
        assert!(changed.client_info.get().is_none());
        assert!(changed.state.is_none());

        changed
            .client_info
            .set(profile(CURRENT_MAC_CLIENT_INFO, CURRENT_MAC_USER_AGENT))
            .unwrap();
        changed.state = Some(provisioned_fixture());
        let replacement = SharedStorage::default();
        replacement.store("backend", "replacement").unwrap();
        let changed = changed.set_storage(Box::new(replacement));
        assert!(changed.state.is_none());
        assert_eq!(
            changed.client_info.get().unwrap().client_info,
            CURRENT_MAC_CLIENT_INFO
        );
        assert_eq!(
            changed.storage.retrieve("backend").unwrap().as_deref(),
            Some("replacement")
        );
    }
}
