use futures::FutureExt;
use isideload::{
    anisette::remote_v3::RemoteV3AnisetteProvider,
    auth::apple_account::{AppleAccount, TwoFactorCallbackParams, TwoFactorCallbackResponse},
    dev::{
        app_ids::{AppIdsApi, ListAppIdsResponse},
        certificates::{CertificatesApi, DevelopmentCertificate},
        developer_session::DeveloperSession,
    },
    sideload::{
        SideloaderBuilder,
        builder::{ExtensionsBehavior, ExtensionsBehaviorSelection, MaxCertsBehavior},
        sideloader::Sideloader,
    },
    util::callbacks::{ExtensionsBehaviorCallbackBox, MaxCertsCallbackBox},
};
use keyring::Entry;
use rootcause::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;
use tauri::{AppHandle, Emitter, Listener, State, Window};
use tauri_plugin_store::StoreExt;
use tracing::debug;

use crate::{
    error::AppError,
    secure_storage::{KEYRING_SERVICE, create_sideloading_storage},
    sideload::{SideloaderGuard, SideloaderMutex},
};

// All windows share the response event, so only one sign-in may own it at a time.
static LOGIN_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tauri::command]
pub async fn login_new(
    handle: AppHandle,
    window: Window,
    sideloader_state: State<'_, SideloaderMutex>,
    email: String,
    password: String,
    anisette_server: String,
    save_credentials: bool,
) -> Result<(), AppError> {
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    if save_credentials {
        let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
            AppError::KeyringWithMessage(
                "Failed to create entry for credentials".into(),
                e.to_string(),
            )
        })?;
        pass_entry.set_password(&password).map_err(|e| {
            AppError::KeyringWithMessage("Failed to save credentials".into(), e.to_string())
        })?;
        let store = handle
            .store("data.json")
            .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
        let mut existing_ids = store
            .get("ids")
            .unwrap_or_else(|| Value::Array(vec![]))
            .as_array()
            .cloned()
            .unwrap_or_else(std::vec::Vec::new);
        let value = Value::String(email.clone());
        if !existing_ids.contains(&value) {
            existing_ids.push(value);
        }
        store.set("ids", Value::Array(existing_ids));
    }
    Ok(())
}

#[tauri::command]
pub async fn login_stored(
    handle: AppHandle,
    window: Window,
    email: String,
    anisette_server: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".to_string(),
            e.to_string(),
        )
    })?;
    let password = pass_entry.get_password().map_err(|e| {
        AppError::KeyringWithMessage("Failed to get credentials".to_string(), e.to_string())
    })?;
    let account = login(&handle, window, &email, &password, anisette_server).await?;
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = Some(account);

    Ok(())
}

#[tauri::command]
pub fn delete_account(handle: AppHandle, email: String) -> Result<(), AppError> {
    let store = handle
        .store("data.json")
        .map_err(|e| AppError::Misc(format!("Failed to get store: {:?}", e)))?;
    let mut existing_ids = store
        .get("ids")
        .unwrap_or_else(|| Value::Array(vec![]))
        .as_array()
        .cloned()
        .unwrap_or_else(std::vec::Vec::new);
    existing_ids.retain(|v| v.as_str().is_none_or(|s| s != email));
    store.set("ids", Value::Array(existing_ids));
    let pass_entry = Entry::new(KEYRING_SERVICE, &email).map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for credentials".into(),
            e.to_string(),
        )
    })?;
    pass_entry.delete_credential().map_err(|e| {
        AppError::KeyringWithMessage("Failed to delete credentials".into(), e.to_string())
    })?;
    Ok(())
}

#[tauri::command]
pub fn logged_in_as(sideloader_state: State<'_, SideloaderMutex>) -> Option<String> {
    let sideloader_guard = sideloader_state.lock().unwrap();
    sideloader_guard
        .as_ref()
        .map(|account| account.get_email().to_string())
}

#[tauri::command]
pub fn invalidate_account(sideloader_state: State<'_, SideloaderMutex>) {
    let mut sideloader_guard = sideloader_state.lock().unwrap();
    *sideloader_guard = None;
}

#[tauri::command]
pub fn reset_anisette_state() -> Result<bool, AppError> {
    let state_entry = Entry::new(KEYRING_SERVICE, "anisette_state").map_err(|e| {
        AppError::KeyringWithMessage(
            "Failed to create keyring entry for anisette".into(),
            e.to_string(),
        )
    })?;

    match state_entry.delete_credential() {
        Ok(_) => {
            debug!("Anisette state deleted from keyring.");
            Ok(true)
        }
        Err(keyring::Error::NoEntry) => {
            debug!("No existing anisette state found in keyring, nothing to delete.");
            Ok(false)
        }
        Err(e) => Err(AppError::KeyringWithMessage(
            "Failed to delete anisette state".into(),
            e.to_string(),
        )),
    }
}

async fn login(
    app: &AppHandle,
    window: Window,
    email: &str,
    password: &str,
    anisette_server: String,
) -> Result<Sideloader<MaxCertsCallbackBox, ExtensionsBehaviorCallbackBox>, AppError> {
    let _login_guard = LOGIN_LOCK.try_lock().map_err(|_| {
        AppError::Misc("A sign-in is already in progress. Complete or cancel it first.".into())
    })?;
    let tfa_closure = {
        let window_clone = window.clone();
        move |params: TwoFactorCallbackParams| {
            let window_clone = window_clone.clone();

            async move {
                if params.sms || params.unknown {
                    bail!("This build only supports trusted-device verification");
                }

                // Register before displaying the dialog so a fast response cannot be lost.
                let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(1);
                let handler_id = window_clone.listen("2fa-response", move |event| {
                    let _ = tx.try_send(event.payload().to_owned());
                });

                if let Err(error) = window_clone.emit("2fa-required", params) {
                    window_clone.unlisten(handler_id);
                    return Err(report!(error)
                        .context("Failed to emit 2fa-required event")
                        .into());
                }

                let result = tokio::time::timeout(Duration::from_secs(300), rx.recv()).await;
                window_clone.unlisten(handler_id);
                let _ = window_clone.emit("2fa-finished", ());

                let payload = result
                    .context("Timed out waiting for a trusted-device verification code")?
                    .context("Trusted-device verification dialog closed")?;
                let response: TwoFactorCallbackResponse = serde_json::from_str(&payload)
                    .context("Invalid trusted-device verification response")?;
                match response {
                    TwoFactorCallbackResponse::SubmitCode(ref code)
                        if code.len() == 6 && code.bytes().all(|b| b.is_ascii_digit()) =>
                    {
                        Ok(response)
                    }
                    TwoFactorCallbackResponse::ResendCode | TwoFactorCallbackResponse::Abort => {
                        Ok(response)
                    }
                    _ => bail!("Expected a six-digit trusted-device code, resend, or cancel"),
                }
            }
            .boxed()
        }
    };

    let anisette_url = if !anisette_server.starts_with("http") {
        format!("https://{}", anisette_server)
    } else {
        anisette_server
    };

    let mut account = AppleAccount::builder(&email.to_lowercase())
        .anisette_provider(
            RemoteV3AnisetteProvider::default()?
                .set_serial_number("0".to_string())
                .set_storage(create_sideloading_storage(app)?)
                .set_url(&anisette_url),
        )
        .login(password, Box::new(tfa_closure))
        .await?;

    debug!("Logged in");

    let dev_session = DeveloperSession::from_account(&mut account).await?;

    debug!("Created developer session");

    let max_certs_callback: MaxCertsCallbackBox =
        Box::new(move |certs: Vec<DevelopmentCertificate>| {
            let window_clone = window.clone();
            Box::pin(async move {
                let cert_infos: Vec<CertificateInfo> = certs
                    .iter()
                    .map(|cert| CertificateInfo {
                        name: cert.name.clone(),
                        certificate_id: cert.certificate_id.clone(),
                        serial_number: cert.serial_number.clone(),
                        machine_name: cert.machine_name.clone(),
                        machine_id: cert.machine_id.clone(),
                    })
                    .collect();
                window_clone.emit("max-certs-reached", cert_infos)?;

                let (tx, rx) = std::sync::mpsc::channel::<Option<Vec<String>>>();
                let handler_id = window_clone.listen("max-certs-response", move |event| {
                    let certs = event.payload();
                    let certs = serde_json::from_str::<Option<Vec<String>>>(certs).unwrap_or(None);
                    let _ = tx.send(certs);
                });

                let result = rx.recv_timeout(Duration::from_secs(300));
                window_clone.unlisten(handler_id);
                Ok(result?)
            })
        });

    // TODO: Team Selection

    let sideloader = SideloaderBuilder::new(dev_session, email.to_lowercase())
        .machine_name("iloader".into())
        .storage(create_sideloading_storage(app)?)
        .extensions_behavior(ExtensionsBehaviorSelection::Fixed(
            ExtensionsBehavior::ReuseMain,
        ))
        .max_certs_behavior(MaxCertsBehavior::Prompt(max_certs_callback))
        .build();

    debug!("Built sideloader");

    Ok(sideloader)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateInfo {
    pub name: Option<String>,
    pub certificate_id: Option<String>,
    pub serial_number: Option<String>,
    pub machine_name: Option<String>,
    pub machine_id: Option<String>,
}

#[tauri::command]
pub async fn get_certificates(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<Vec<CertificateInfo>, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let certificates = dev_session.list_all_development_certs(&team, None).await?;

    Ok(certificates
        .into_iter()
        .map(|cert| CertificateInfo {
            name: cert.name,
            certificate_id: cert.certificate_id,
            serial_number: cert.serial_number,
            machine_name: cert.machine_name,
            machine_id: cert.machine_id,
        })
        .collect())
}

#[tauri::command]
pub async fn revoke_certificate(
    serial_number: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session
        .revoke_development_cert(&team, &serial_number, None)
        .await?;

    Ok(())
}

#[tauri::command]
pub async fn list_app_ids(
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<ListAppIdsResponse, AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    let response = dev_session.list_app_ids(&team, None).await?;

    Ok(response.clone())
}

#[tauri::command]
pub async fn delete_app_id(
    app_id_id: String,
    sideloader_state: State<'_, SideloaderMutex>,
) -> Result<(), AppError> {
    let mut sideloader = SideloaderGuard::take(&sideloader_state)?;

    let team = sideloader.get_mut().get_team().await?;
    let dev_session = sideloader.get_mut().get_dev_session();

    dev_session.delete_app_id(&team, &app_id_id, None).await?;

    Ok(())
}
