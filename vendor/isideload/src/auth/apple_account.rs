use std::sync::Arc;

use crate::util::callbacks::TwoFactorCallback;
use crate::{
    SideloadError,
    anisette::{AnisetteData, AnisetteDataGenerator},
    auth::{
        builder::AppleAccountBuilder,
        grandslam::{GrandSlam, GrandSlamErrorChecker},
    },
    util::plist::{PlistDataExtract, SensitivePlistAttachment},
};
use aes::{
    Aes256,
    cipher::{block_padding::Pkcs7, consts::U16},
};
use aes_gcm::{AeadInOut, AesGcm, KeyInit, Nonce};
use base64::{Engine, prelude::BASE64_STANDARD};
use cbc::cipher::{BlockModeDecrypt, KeyIvInit};
use hmac::{Hmac, Mac};
use plist::Dictionary;
use plist_macro::plist;
use reqwest::header::{HeaderMap, HeaderValue};
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use srp::{ClientVerifier, groups::G2048};
use tracing::{debug, info, warn};

pub struct AppleAccount {
    pub email: String,
    pub spd: Option<plist::Dictionary>,
    pub anisette_generator: AnisetteDataGenerator,
    pub grandslam_client: Arc<GrandSlam>,
    pub trusted_phone_numbers: Option<Vec<TrustedNumber>>,
    login_state: LoginState,
    debug: bool,
    last_error: Option<String>,
    err_429_retries: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginState {
    LoggedIn,
    NeedsDevice2FA,
    NeedsDevice2FAVerification,
    NeedsSMS2FA(u32),
    NeedsSMS2FAVerification(u32),
    NeedsUnknown2FA,
    NeedsExtraStep(String),
    NeedsLogin,
}

/// This vendored build supports trusted-device authentication only. Normalize
/// legacy/resumed SMS states before dispatch, including an already-sent SMS.
fn trusted_device_only_state(state: LoginState) -> LoginState {
    match state {
        LoginState::NeedsSMS2FA(_)
        | LoginState::NeedsSMS2FAVerification(_)
        | LoginState::NeedsUnknown2FA => LoginState::NeedsDevice2FA,
        other => other,
    }
}

fn login_state_from_status(status: &Dictionary) -> Result<LoginState, Report> {
    if let Some(plist::Value::String(method)) = status.get("au") {
        return Ok(match method.as_str() {
            "trustedDeviceSecondaryAuth" | "secondaryAuth" => LoginState::NeedsDevice2FA,
            "repair" => LoginState::LoggedIn,
            other => LoginState::NeedsExtraStep(other.to_owned()),
        });
    }

    if let Some(plist::Value::Integer(status_code)) = status.get("hsc") {
        match status_code.as_signed() {
            Some(200) => {}
            Some(409) => {
                // A resumed challenge may have been created by the old SMS
                // client. Explicitly request a device code instead of assuming
                // the pending challenge used the trusted-device channel.
                info!("Pending 2FA challenge; requesting trusted-device verification");
                return Ok(LoginState::NeedsDevice2FA);
            }
            other => bail!("Unexpected Apple login status code {:?}", other),
        }
    }

    Ok(LoginState::LoggedIn)
}

#[derive(Debug, PartialEq, Eq)]
enum TrustedDeviceAction {
    Verify(String),
    RequestCode,
}

fn trusted_device_action(
    response: TwoFactorCallbackResponse,
) -> Result<TrustedDeviceAction, Report> {
    match response {
        TwoFactorCallbackResponse::SubmitCode(code) => Ok(TrustedDeviceAction::Verify(code)),
        TwoFactorCallbackResponse::SendToDevices | TwoFactorCallbackResponse::ResendCode => {
            Ok(TrustedDeviceAction::RequestCode)
        }
        TwoFactorCallbackResponse::SendSms(_) => {
            bail!("SMS authentication is disabled in this build. Use a trusted Apple device.")
        }
        TwoFactorCallbackResponse::Abort => bail!("Two-factor authentication canceled"),
    }
}

/// Bound repeated challenges separately from the existing login-transition
/// budget. An accepted code must finish login, not start another challenge loop.
#[derive(Default)]
struct TrustedDeviceProgress {
    requests: u8,
    accepted_code: bool,
}

impl TrustedDeviceProgress {
    fn check_state(&self, state: &LoginState) -> Result<(), Report> {
        if self.accepted_code
            && matches!(
                state,
                LoginState::NeedsDevice2FA | LoginState::NeedsDevice2FAVerification
            )
        {
            bail!(
                "Apple accepted the trusted-device code but requested verification again. \
                 Login stopped; SMS authentication remains disabled."
            );
        }
        Ok(())
    }

    fn request_code(&mut self) -> Result<(), Report> {
        if self.requests >= 3 {
            bail!(
                "Stopped after three trusted-device code requests. \
                 Try again later; SMS authentication remains disabled."
            );
        }
        self.requests += 1;
        Ok(())
    }

    fn verified(&mut self, state: &LoginState) {
        if matches!(state, LoginState::NeedsLogin) {
            self.accepted_code = true;
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrustedNumber {
    pub number_with_dial_code: String,
    pub last_two_digits: String,
    pub push_mode: String,
    pub id: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TwoFactorCallbackParams {
    pub last_error: Option<String>,
    // If this is true, we don't know what's going to work, so present the user with all the options and let them choose
    pub unknown: bool,
    pub sms: bool,
    pub numbers: Vec<TrustedNumber>,
    pub selected_number_id: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TwoFactorCallbackResponse {
    SubmitCode(String),
    SendSms(u32),
    SendToDevices,
    ResendCode,
    Abort,
}

#[derive(Debug, Clone)]
pub struct SMSTwoFactorError {
    pub code: String,
    pub title: String,
    pub message: String,
}

/// Extracts the resync SIM (base64 `X-Apple-I-MD-DATA`) from a GSA response that
/// demands an anisette resync (`Status.hsc == 434`); `None` otherwise.
fn resync_sim(resp: &plist::Dictionary) -> Option<String> {
    use base64::prelude::*;
    let status = resp.get("Status")?.as_dictionary()?;
    if status.get("hsc").and_then(plist::Value::as_signed_integer) != Some(434) {
        return None;
    }
    match status.get("X-Apple-I-MD-DATA")? {
        plist::Value::Data(d) => Some(BASE64_STANDARD.encode(d)),
        plist::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

impl AppleAccount {
    /// Create a new AppleAccountBuilder with the given email
    ///
    /// # Arguments
    /// - `email`: The Apple ID email address
    pub fn builder(email: &str) -> AppleAccountBuilder {
        AppleAccountBuilder::new(email)
    }

    /// Build the apple account with the given email
    ///
    /// Reccomended to use the AppleAccountBuilder instead
    /// # Arguments
    /// - `email`: The Apple ID email address
    /// - `anisette_provider`: The anisette provider to use
    /// - `debug`: DANGER, If true, accept invalid certificates and enable verbose connection
    pub async fn new(
        email: &str,
        anisette_generator: AnisetteDataGenerator,
        debug: bool,
        proxy_url: Option<String>,
        err_429_retries: Option<u32>,
    ) -> Result<Self, Report> {
        if debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        let client_info = anisette_generator
            .get_client_info()
            .await
            .context("Failed to get anisette client info")?;

        let grandslam_client = GrandSlam::new(client_info, debug, proxy_url.clone()).await?;

        Ok(AppleAccount {
            email: email.to_string(),
            spd: None,
            anisette_generator,
            grandslam_client: Arc::new(grandslam_client),
            debug,
            login_state: LoginState::NeedsLogin,
            trusted_phone_numbers: None,
            last_error: None,
            err_429_retries,
        })
    }

    /// Log in to the Apple ID account
    /// # Arguments
    /// - `password`: The Apple ID password
    /// - `two_factor_callback`: A callback function that returns the two-factor authentication code
    /// # Errors
    /// Returns an error if the login fails
    pub async fn login<C>(&mut self, password: &str, two_factor_callback: C) -> Result<(), Report>
    where
        C: TwoFactorCallback,
    {
        self.login_impl(password, two_factor_callback).await
    }

    async fn login_impl<C>(&mut self, password: &str, two_factor_callback: C) -> Result<(), Report>
    where
        C: TwoFactorCallback,
    {
        info!("Logging in to Apple ID: {}", censor_email(&self.email));
        if self.debug {
            warn!("Debug mode enabled: this is a security risk!");
        }

        self.login_state = self
            .login_inner(password)
            .await
            .context("Failed to log in to Apple ID")?;

        debug!("Initial login successful");

        let mut attempts = 0;
        let mut progress = TrustedDeviceProgress::default();

        loop {
            attempts += 1;
            if attempts > 15 {
                bail!(
                    "Couldn't login after 15 attempts, aborting (current state: {:?})",
                    self.login_state
                );
            }
            self.login_state = trusted_device_only_state(self.login_state.clone());
            progress.check_state(&self.login_state)?;
            match self.login_state.clone() {
                LoginState::LoggedIn => {
                    info!("Successfully logged in to Apple ID");
                    return Ok(());
                }
                LoginState::NeedsDevice2FA => {
                    progress.request_code()?;
                    self.send_trusted_device_2fa().await.context(
                        "Could not request trusted-device verification. Sign this Apple \
                             Account into a trusted Apple device and try again. \
                             This build will not fall back to SMS.",
                    )?;
                    self.login_state = LoginState::NeedsDevice2FAVerification;
                }
                LoginState::NeedsDevice2FAVerification => {
                    let response = two_factor_callback(TwoFactorCallbackParams {
                        last_error: self.last_error.clone(),
                        unknown: false,
                        sms: false,
                        numbers: Vec::new(),
                        selected_number_id: None,
                    })
                    .await?;
                    self.last_error = None;
                    match trusted_device_action(response)? {
                        TrustedDeviceAction::Verify(code) => {
                            self.login_state = self
                                .verify_trusted_device_2fa(code)
                                .await
                                .context("Failed to verify trusted device 2FA")?;
                            progress.verified(&self.login_state);
                        }
                        TrustedDeviceAction::RequestCode => {
                            self.login_state = LoginState::NeedsDevice2FA;
                        }
                    }
                }
                LoginState::NeedsExtraStep(s) => {
                    info!("Additional authentication step required: {}", s);
                    if self.get_pet().is_err() {
                        bail!("Additional authentication required: {}", s);
                    }
                    self.login_state = LoginState::LoggedIn;
                }
                LoginState::NeedsLogin => {
                    debug!("Logging in again...");
                    self.login_state = self
                        .login_inner(password)
                        .await
                        .context("Failed to login again")?;
                }
                LoginState::NeedsSMS2FA(_)
                | LoginState::NeedsSMS2FAVerification(_)
                | LoginState::NeedsUnknown2FA => {
                    bail!("Unsupported authentication state; SMS remains disabled.");
                }
            }
        }
    }

    /// Get the user's first and last name associated with the Apple ID
    pub fn get_name(&self) -> Result<(String, String), Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get name"))?;

        Ok((spd.get_string("fn")?, spd.get_string("ln")?))
    }

    fn get_pet(&self) -> Result<String, Report> {
        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD not available, cannot get pet"))?;

        let pet = spd
            .get_dict("t")?
            .get_dict("com.apple.gs.idms.pet")?
            .get_string("token")?;

        Ok(pet)
    }

    async fn send_trusted_device_2fa(&mut self) -> Result<(), Report> {
        debug!("Trusted device 2FA required");

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let request_code_url = self
            .grandslam_client
            .get_url("trustedDeviceSecondaryAuth")?;

        let response = self
            .grandslam_client
            .get(&request_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .send()
            .await
            .context("Failed to request trusted device 2fa")?;
        if !response.status().is_success() {
            bail!(
                "Trusted-device code request failed with HTTP {}. \
                 Apple did not complete this verification request; no SMS was requested.",
                response.status().as_u16()
            );
        }

        info!("Trusted device 2FA request sent");

        Ok(())
    }

    async fn verify_trusted_device_2fa(&mut self, code: String) -> Result<LoginState, Report> {
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for 2FA")?;

        let submit_code_url = self.grandslam_client.get_url("validateCode")?;

        let res = self
            .grandslam_client
            .get(&submit_code_url)?
            .headers(self.build_2fa_headers(&anisette_data).await?)
            .header("security-code", code)
            .send()
            .await
            .context("Failed to submit trusted device 2fa code")?
            .error_for_status()
            .context("Trusted device 2FA code submission failed")?
            .text()
            .await
            .context("Failed to read trusted device 2FA response text")?;

        let plist: Dictionary = plist::from_bytes(res.as_bytes())
            .context("Failed to parse trusted device response plist")
            .attach_with(|| res.clone())?;
        let res = plist
            .check_grandslam_error()
            .context("Trusted device 2FA rejected");
        if let Err(ref report) = res {
            for cause in report.iter_reports() {
                if let Some(err) = cause.downcast_current_context::<SideloadError>() {
                    match err {
                        &SideloadError::AuthWithMessage(code, ref message) => match code {
                            // Incorrect Verification Code, let the user try again
                            -21669 => {
                                warn!("{} - {}", code, message);
                                self.last_error = format!("{} - {}", code, message).into();

                                return Ok(LoginState::NeedsDevice2FAVerification);
                            }
                            _ => {}
                        },
                        _ => {}
                    }
                }
            }
        }
        res?;

        debug!("Trusted device 2FA completed, need to login again");

        Ok(LoginState::NeedsLogin)
    }

    async fn build_2fa_headers(&self, anisette_data: &AnisetteData) -> Result<HeaderMap, Report> {
        let mut headers = anisette_data.get_header_map()?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot build 2FA headers"))?;

        let adsid = spd
            .get_str("adsid")
            .context("Failed to build 2FA headers")?;
        let token = spd
            .get_str("GsIdmsToken")
            .context("Failed to build 2FA headers")?;
        let identity = BASE64_STANDARD.encode(format!("{}:{}", adsid, token));

        headers.insert(
            "X-Apple-Identity-Token",
            reqwest::header::HeaderValue::from_str(&identity)?,
        );
        headers.insert(
            "X-Apple-I-MD-RINFO",
            reqwest::header::HeaderValue::from_str(&anisette_data.routing_info)?,
        );

        Ok(headers)
    }

    async fn login_inner(&mut self, password: &str) -> Result<LoginState, Report> {
        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;

        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        debug!("GrandSlam service URL: {}", gs_service_url);

        let cpd = anisette_data.get_client_provided_data();

        let srp_client = srp::Client::<G2048, Sha256>::new_with_options(false);
        let a: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
        let a_pub = srp_client.compute_public_ephemeral(&a);

        let mut raw_response = self
            .send_init_request(&gs_service_url, &cpd, &a_pub)
            .await?;

        if let Some(sim) = resync_sim(&raw_response) {
            debug!("Anisette resync required (hsc 434); syncing then retrying init");
            let fresh_anisette = self
                .anisette_generator
                .resync(&sim)
                .await
                .context("Anisette resync failed")?;
            let fresh_cpd = fresh_anisette.get_client_provided_data();
            raw_response = self
                .send_init_request(&gs_service_url, &fresh_cpd, &a_pub)
                .await
                .context("Failed to send resynced init request")?;
        }
        let response = raw_response
            .check_grandslam_error()
            .context("GrandSlam error during initial login request")?;

        debug!("Login step 1 completed");

        let salt = response
            .get_data("s")
            .context("Failed to parse initial login response")?;
        let b_pub = response
            .get_data("B")
            .context("Failed to parse initial login response")?;
        let iters = response
            .get_signed_integer("i")
            .context("Failed to parse initial login response")?;
        let c = response
            .get_str("c")
            .context("Failed to parse initial login response")?;
        let selected_protocol = response
            .get_str("sp")
            .context("Failed to parse initial login response")?;

        debug!(
            "Selected SRP protocol: {}, iterations: {}",
            selected_protocol, iters
        );

        if selected_protocol != "s2k" && selected_protocol != "s2k_fo" {
            bail!("Unsupported SRP protocol selected: {}", selected_protocol);
        }

        let hashed_password = Sha256::digest(password.as_bytes());

        let password_hash = if selected_protocol == "s2k_fo" {
            hex::encode(hashed_password).into_bytes()
        } else {
            hashed_password.to_vec()
        };

        let mut password_buf = [0u8; 32];
        pbkdf2::pbkdf2::<hmac::Hmac<Sha256>>(&password_hash, salt, iters as u32, &mut password_buf)
            .context("Failed to derive password using PBKDF2")?;

        let verifier = srp_client
            .process_reply(&a, self.email.as_bytes(), &password_buf, salt, b_pub)
            .context("Failed to compute SRP proof")?;

        let req2 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "M1": verifier.proof().to_vec(), // A2k = client public ephemeral
                "c": c, // c = client proof from step 1
                "cpd": cpd, // cpd = client provided data
                "o": "complete", // o = operation
                "u": self.email.clone(), // u = username
            }
        });

        debug!("Sending proof login request");

        let mut close_headers = HeaderMap::new();
        close_headers.insert("Connection", HeaderValue::from_static("close"));

        let response2 = self
            .grandslam_client
            .plist_request(
                &gs_service_url,
                &req2,
                Some(close_headers),
                self.err_429_retries,
            )
            .await
            .context("Failed to send proof login request")?
            .check_grandslam_error()
            .context("GrandSlam error during proof login request")?;

        debug!("Login step 2 response received, verifying server proof");

        let m2 = response2
            .get_data("M2")
            .context("Failed to parse proof login response")?;
        verifier
            .verify_server(m2)
            .map_err(|e| report!("Negotiation failed, server proof mismatch: {}", e))?;

        debug!("Server proof verified");

        let spd_encrypted = response2
            .get_data("spd")
            .context("Failed to get SPD from login response")?;

        let spd_decrypted = Self::decrypt_cbc(&verifier, spd_encrypted)
            .context("Failed to decrypt SPD from login response")?;
        let spd: plist::Dictionary =
            plist::from_bytes(&spd_decrypted).context("Failed to parse decrypted SPD plist")?;

        self.spd = Some(spd);

        let status = response2
            .get_dict("Status")
            .context("Failed to parse proof login response")?;

        debug!("Login step 2 completed");

        login_state_from_status(status)
    }

    pub async fn get_app_token(&mut self, app: &str) -> Result<AppToken, Report> {
        let app = if app.contains("com.apple.gs.") {
            app.to_string()
        } else {
            format!("com.apple.gs.{}", app)
        };

        let anisette_data = self
            .anisette_generator
            .get_anisette_data(self.grandslam_client.clone())
            .await
            .context("Failed to get anisette data for login")?;

        let spd = self
            .spd
            .as_ref()
            .ok_or_else(|| report!("SPD data not available, cannot get app token"))?;

        let dsid = spd.get_str("adsid").context("Failed to get app token")?;
        let auth_token = spd
            .get_str("GsIdmsToken")
            .context("Failed to get app token")?;
        let session_key = spd.get_data("sk").context("Failed to get app token")?;
        let c = spd.get_data("c").context("Failed to get app token")?;

        let checksum = Hmac::<Sha256>::new_from_slice(session_key)
            .context("Failed to create HMAC for app token checksum")
            .attach_with(|| SensitivePlistAttachment::new(spd.clone()))?
            .chain_update("apptokens".as_bytes())
            .chain_update(dsid.as_bytes())
            .chain_update(app.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec();

        let gs_service_url = self.grandslam_client.get_url("gsService")?;
        let cpd = anisette_data.get_client_provided_data();

        let request = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "app": [app.clone()],
                "c": c,
                "checksum": checksum,
                "cpd": cpd,
                "o": "apptokens",
                "u": dsid,
                "t": auth_token
            }
        });

        let resp = self
            .grandslam_client
            .plist_request(&gs_service_url, &request, None, self.err_429_retries)
            .await
            .context("Failed to send app token request")?
            .check_grandslam_error()
            .context("GrandSlam error during app token request")?;

        let encrypted_token = resp
            .get_data("et")
            .context("Failed to get encrypted token")?;

        debug!("Acquired encrypted token for {}", app);
        let decrypted_token = Self::decrypt_gcm(encrypted_token, session_key)
            .context("Failed to decrypt app token")?;
        debug!("Decrypted app token for {}", app);

        let token: Dictionary = plist::from_bytes(&decrypted_token)
            .context("Failed to parse decrypted app token plist")?;

        let status = token
            .get_signed_integer("status-code")
            .context("Failed to get status code from app token")?;
        if status != 200 {
            bail!("App token request failed with status code {}", status);
        }
        let token_dict = token
            .get_dict("t")
            .context("Failed to get token dictionary from app token")?;
        let app_token = token_dict
            .get_dict(&app)
            .context("Failed to get app token string")?;

        let app_token = AppToken {
            token: app_token
                .get_str("token")
                .context("Failed to get app token string")?
                .to_string(),
            duration: app_token
                .get_signed_integer("duration")
                .context("Failed to get app token duration")? as u64,
            expiry: app_token
                .get_signed_integer("expiry")
                .context("Failed to get app token expiry")? as u64,
        };

        info!("Successfully retrieved app token for {}", app);

        Ok(app_token)
    }

    async fn send_init_request(
        &mut self,
        gs_service_url: &str,
        cpd: &Dictionary,
        a_pub: &Vec<u8>,
    ) -> Result<Dictionary, Report> {
        debug!("Sending initial login request");
        let req1 = plist!(dict {
            "Header": {
                "Version": "1.0.1"
            },
            "Request": {
                "A2k": a_pub.clone(), // A2k = client public ephemeral
                "cpd": cpd.clone(), // cpd = client provided data
                "o": "init", // o = operation
                "ps": [ // ps = protocols supported
                    "s2k", // password sent as sha256
                    "s2k_fo" // password sent as utf8 hex string of sha256
                ],
                "u": self.email.clone(), // u = username
            }
        });

        Ok(self
            .grandslam_client
            .plist_request(gs_service_url, &req1, None, self.err_429_retries)
            .await
            .context("Failed to send initial login request")?)
    }

    fn create_session_key(usr: &ClientVerifier<Sha256>, name: &str) -> Result<Vec<u8>, Report> {
        Ok(Hmac::<Sha256>::new_from_slice(usr.key())?
            .chain_update(name.as_bytes())
            .finalize()
            .into_bytes()
            .to_vec())
    }

    fn decrypt_cbc(usr: &ClientVerifier<Sha256>, data: &[u8]) -> Result<Vec<u8>, Report> {
        let extra_data_key = Self::create_session_key(usr, "extra data key:")?;
        let extra_data_iv = Self::create_session_key(usr, "extra data iv:")?;
        let extra_data_iv = &extra_data_iv[..16];

        Ok(
            cbc::Decryptor::<aes::Aes256>::new_from_slices(&extra_data_key, extra_data_iv)?
                .decrypt_padded_vec::<Pkcs7>(data)?,
        )
    }

    fn decrypt_gcm(data: &[u8], key: &[u8]) -> Result<Vec<u8>, Report> {
        if data.len() < 3 + 16 + 16 {
            bail!(
                "Encrypted token is too short to be valid (only {} bytes)",
                data.len()
            );
        }
        let header = &data[0..3];
        if header != b"XYZ" {
            bail!(
                "Encrypted token is in an unknown format: {}",
                String::from_utf8_lossy(header)
            );
        }
        let iv = &data[3..19];
        let ciphertext_and_tag = &data[19..];

        if key.len() != 32 {
            bail!("Session key is not the correct length: {} bytes", key.len());
        }
        if iv.len() != 16 {
            bail!("IV is not the correct length: {} bytes", iv.len());
        }

        debug!(
            "Decrypting GCM data with key of length {} and IV of length {}",
            key.len(),
            iv.len()
        );
        let key = aes_gcm::Key::<AesGcm<Aes256, U16>>::try_from(key)?;
        debug!("GCM key created successfully");
        let cipher = AesGcm::<Aes256, U16>::new(&key);
        debug!("GCM cipher initialized successfully");
        let nonce = Nonce::<U16>::try_from(iv)?;
        debug!("GCM nonce created successfully");

        let mut buf = ciphertext_and_tag.to_vec();

        cipher
            .decrypt_in_place(&nonce, header, &mut buf)
            .map_err(|e| report!("Failed to decrypt gcm: {}", e))?;
        debug!("GCM decryption successful");

        Ok(buf)
    }
}

impl std::fmt::Display for AppleAccount {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Apple Account: ")?;
        match self.get_name() {
            Ok((first, last)) => write!(f, "{} {} ", first, last),
            Err(_) => Ok(()),
        }?;
        write!(f, "{} ({:?})", self.email, self.login_state)
    }
}

#[derive(Debug, Clone)]
pub struct AppToken {
    pub token: String,
    pub duration: u64,
    pub expiry: u64,
}

fn censor_email(email: &str) -> String {
    if std::env::var("DEBUG_SENSITIVE").is_ok() {
        return email.to_string();
    }
    if let Some(at_pos) = email.find('@') {
        let (local, domain) = email.split_at(at_pos);
        if local.len() <= 2 {
            format!("{}***{}", &local[0..1], &domain)
        } else {
            format!(
                "{}***{}{}",
                &local[0..1],
                &local[local.len() - 1..],
                &domain
            )
        }
    } else {
        "***".to_string()
    }
}

#[cfg(test)]
mod trusted_device_tests {
    use super::*;

    #[test]
    fn apple_sms_hint_requests_a_trusted_device_challenge() {
        for method in ["secondaryAuth", "trustedDeviceSecondaryAuth"] {
            let mut status = Dictionary::new();
            status.insert("au".into(), plist::Value::String(method.into()));
            assert_eq!(
                login_state_from_status(&status).unwrap(),
                LoginState::NeedsDevice2FA
            );
        }
    }

    #[test]
    fn pending_challenge_does_not_reuse_an_old_sms_code() {
        let mut status = Dictionary::new();
        status.insert("hsc".into(), plist::Value::Integer(409.into()));
        assert_eq!(
            login_state_from_status(&status).unwrap(),
            LoginState::NeedsDevice2FA
        );
    }

    #[test]
    fn resumed_sms_and_unknown_states_require_a_new_device_challenge() {
        for state in [
            LoginState::NeedsSMS2FA(0),
            LoginState::NeedsSMS2FA(u32::MAX),
            LoginState::NeedsSMS2FAVerification(1),
            LoginState::NeedsSMS2FAVerification(u32::MAX),
            LoginState::NeedsUnknown2FA,
        ] {
            assert_eq!(trusted_device_only_state(state), LoginState::NeedsDevice2FA);
        }
        // Retrying an incorrect device code must not send another code or
        // silently convert the partially authenticated session to LoggedIn.
        assert_eq!(
            trusted_device_only_state(LoginState::NeedsDevice2FAVerification),
            LoginState::NeedsDevice2FAVerification
        );
    }

    #[test]
    fn callback_cannot_select_sms_or_turn_abort_into_login() {
        for number in [0, 1, u32::MAX] {
            let error = trusted_device_action(TwoFactorCallbackResponse::SendSms(number))
                .err()
                .expect("SMS callback must fail closed");
            assert!(error.to_string().contains("SMS authentication is disabled"));
        }
        assert!(trusted_device_action(TwoFactorCallbackResponse::Abort).is_err());
    }

    #[test]
    fn code_submission_requires_verification_and_resend_stays_on_device() {
        assert_eq!(
            trusted_device_action(TwoFactorCallbackResponse::SubmitCode("123456".into())).unwrap(),
            TrustedDeviceAction::Verify("123456".into())
        );
        for response in [
            TwoFactorCallbackResponse::SendToDevices,
            TwoFactorCallbackResponse::ResendCode,
        ] {
            assert_eq!(
                trusted_device_action(response).unwrap(),
                TrustedDeviceAction::RequestCode
            );
        }
    }

    #[test]
    fn accepted_code_cannot_start_an_automatic_challenge_loop() {
        let mut progress = TrustedDeviceProgress::default();
        progress.verified(&LoginState::NeedsDevice2FAVerification);
        assert!(
            progress
                .check_state(&LoginState::NeedsDevice2FAVerification)
                .is_ok()
        );

        progress.verified(&LoginState::NeedsLogin);
        assert!(progress.check_state(&LoginState::NeedsLogin).is_ok());
        assert!(progress.check_state(&LoginState::LoggedIn).is_ok());
        for state in [
            LoginState::NeedsDevice2FA,
            LoginState::NeedsDevice2FAVerification,
            LoginState::NeedsSMS2FA(1),
            LoginState::NeedsSMS2FAVerification(1),
        ] {
            assert!(
                progress
                    .check_state(&trusted_device_only_state(state))
                    .is_err()
            );
        }
    }

    #[test]
    fn repeated_resend_is_bounded_without_sms_fallback() {
        let mut progress = TrustedDeviceProgress::default();
        for _ in 0..3 {
            progress.request_code().unwrap();
        }
        for _ in 0..10 {
            assert!(progress.request_code().is_err());
        }
        assert_eq!(progress.requests, 3);
    }

    #[test]
    fn unknown_security_requirements_are_not_treated_as_authenticated() {
        let mut status = Dictionary::new();
        status.insert(
            "au".into(),
            plist::Value::String("additionalSecurityStep".into()),
        );
        assert_eq!(
            login_state_from_status(&status).unwrap(),
            LoginState::NeedsExtraStep("additionalSecurityStep".into())
        );
        status.clear();
        status.insert("hsc".into(), plist::Value::Integer(403.into()));
        assert!(login_state_from_status(&status).is_err());
    }
}

#[cfg(all(test, not(feature = "wasm")))]
#[path = "trusted_device_http_tests.rs"]
mod trusted_device_http_tests;
