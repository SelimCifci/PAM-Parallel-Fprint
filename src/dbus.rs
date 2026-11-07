use futures_util::StreamExt;
use std::time::Duration;
use tokio::sync::oneshot;
use tokio::time::sleep;
use zbus::OwnedObjectPath;
use zbus::connection::Connection;
use zbus::proxy;

use crate::log::log_debug;

#[proxy(
    interface = "net.reactivated.Fprint.Manager",
    default_service = "net.reactivated.Fprint",
    default_path = "/net/reactivated/Fprint/Manager"
)]
pub trait FprintManager {
    fn get_default_device(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_devices(&self) -> zbus::Result<Vec<OwnedObjectPath>>;
}

#[proxy(
    interface = "net.reactivated.Fprint.Device",
    default_service = "net.reactivated.Fprint"
)]
pub trait FprintDevice {
    fn list_enrolled_fingers(&self, username: &str) -> zbus::Result<Vec<String>>;
    fn claim(&self, username: &str) -> zbus::Result<()>;
    fn release(&self) -> zbus::Result<()>;
    fn verify_start(&self, finger_name: &str) -> zbus::Result<()>;
    fn verify_stop(&self) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_status(&self, result: &str, done: bool) -> zbus::Result<()>;

    #[zbus(signal)]
    fn verify_finger_selected(&self, finger_name: &str) -> zbus::Result<()>;
}

#[derive(Debug, PartialEq, Eq)]
pub enum FprintOutcome {
    Matched,
    ExceededTries,
    TimedOut,
    Cancelled,
    DeviceError,
}

/// Upfront check for fast bypass (PAM_IGNORE).
/// Returns Some((Connection, OwnedObjectPath)) if a fingerprint device exists
/// and the specified user has at least one fingerprint enrolled.
pub async fn check_device_and_prints(
    username: &str,
    debug: bool,
) -> Option<(Connection, OwnedObjectPath)> {
    log_debug(debug, &format!("Checking fprintd for user '{}'", username));

    let connection = match Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            log_debug(debug, &format!("Failed to connect to system D-Bus: {}", e));
            return None;
        }
    };

    let manager = match FprintManagerProxy::new(&connection).await {
        Ok(m) => m,
        Err(e) => {
            log_debug(
                debug,
                &format!("Failed to connect to Fprint Manager: {}", e),
            );
            return None;
        }
    };

    let device_path = match manager.get_default_device().await {
        Ok(p) => p,
        Err(e) => {
            log_debug(debug, &format!("No default fprint device found: {}", e));
            return None;
        }
    };

    let device = match FprintDeviceProxy::builder(&connection)
        .path(&device_path)
        .build()
        .await
    {
        Ok(d) => d,
        Err(e) => {
            log_debug(debug, &format!("Failed to connect to device proxy: {}", e));
            return None;
        }
    };

    let mut fingers_res = device.list_enrolled_fingers(username).await;
    for attempt in 1..=3 {
        if let Err(ref e) = fingers_res
            && is_device_busy_error(e)
        {
            log_debug(
                debug,
                &format!(
                    "fprintd is busy during enrolled fingers check (attempt {}/3); retrying in 200ms...",
                    attempt
                ),
            );
            sleep(Duration::from_millis(200)).await;
            fingers_res = device.list_enrolled_fingers(username).await;
            continue;
        }
        break;
    }

    match fingers_res {
        Ok(fingers) if !fingers.is_empty() => {
            log_debug(
                debug,
                &format!("User '{}' has enrolled fingers: {:?}", username, fingers),
            );
            Some((connection, device_path))
        }
        Ok(_) => {
            log_debug(
                debug,
                &format!("User '{}' has 0 enrolled fingers", username),
            );
            None
        }
        Err(e) => {
            log_debug(
                debug,
                &format!(
                    "No enrolled fingers for user '{}' (or error: {})",
                    username, e
                ),
            );
            None
        }
    }
}

/// Runs asynchronous fingerprint verification, listening for signals.
/// Gracefully retries acquiring the fingerprint device if it is busy with
/// another request, while remaining fully cancellable if the user enters a password.
pub async fn run_fprint_verification(
    connection: &Connection,
    device_path: &OwnedObjectPath,
    username: &str,
    max_tries: u32,
    timeout_secs: u64,
    debug: bool,
    mut cancel_rx: oneshot::Receiver<()>,
) -> FprintOutcome {
    let device = match FprintDeviceProxy::builder(connection)
        .path(device_path)
        .build()
        .await
    {
        Ok(d) => d,
        Err(e) => {
            log_debug(debug, &format!("Failed to build device proxy: {}", e));
            return FprintOutcome::DeviceError;
        }
    };

    let timeout_fut = sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout_fut);

    let mut claimed = false;
    let mut busy_logged = false;
    const RETRY_INTERVAL: Duration = Duration::from_millis(250);

    // 1. Acquire device claim and start verification with graceful retry on busy
    let mut status_stream = loop {
        log_debug(debug, "Claiming fingerprint device");
        match device.claim(username).await {
            Ok(()) => {
                if busy_logged {
                    log_debug(
                        debug,
                        "Fingerprint device acquired successfully after previous busy state",
                    );
                }
                claimed = true;

                // Subscribe to verify status before calling verify_start to ensure no signals are dropped
                let stream = match device.receive_verify_status().await {
                    Ok(s) => s,
                    Err(e) => {
                        log_debug(
                            debug,
                            &format!("Failed to subscribe to verify status: {}", e),
                        );
                        let _ = device.release().await;
                        return FprintOutcome::DeviceError;
                    }
                };

                log_debug(debug, "Starting fprint verification");
                match device.verify_start("any").await {
                    Ok(()) => {
                        break stream;
                    }
                    Err(e) => {
                        let _ = device.release().await;
                        claimed = false;
                        if is_device_busy_error(&e) {
                            if !busy_logged {
                                log_debug(
                                    debug,
                                    &format!(
                                        "Fingerprint device busy during verify_start ({}). Retrying gracefully in background...",
                                        e
                                    ),
                                );
                                busy_logged = true;
                            }
                        } else {
                            log_debug(debug, &format!("Failed to start verification: {}", e));
                            return FprintOutcome::DeviceError;
                        }
                    }
                }
            }
            Err(e) => {
                if is_device_busy_error(&e) {
                    if !busy_logged {
                        log_debug(
                            debug,
                            &format!(
                                "Fingerprint device is busy with another request ({}). Retrying gracefully in background...",
                                e
                            ),
                        );
                        busy_logged = true;
                    }
                } else {
                    log_debug(debug, &format!("Failed to claim fingerprint device: {}", e));
                    return FprintOutcome::DeviceError;
                }
            }
        }

        // Wait before retrying, remaining fully responsive to cancel (password entry) and timeout
        tokio::select! {
            _ = &mut cancel_rx => {
                log_debug(debug, "fprintd verification cancelled while waiting for busy device");
                if claimed {
                    let _ = device.release().await;
                }
                return FprintOutcome::Cancelled;
            }
            _ = &mut timeout_fut => {
                log_debug(debug, "fprintd verification timed out while waiting for busy device");
                if claimed {
                    let _ = device.release().await;
                }
                return FprintOutcome::TimedOut;
            }
            _ = sleep(RETRY_INTERVAL) => {}
        }
    };

    let mut tries = 0;

    let outcome = loop {
        tokio::select! {
            _ = &mut cancel_rx => {
                log_debug(debug, "fprintd verification cancelled by password entry or termination");
                break FprintOutcome::Cancelled;
            }
            _ = &mut timeout_fut => {
                log_debug(debug, "fprintd verification timed out");
                break FprintOutcome::TimedOut;
            }
            signal_opt = status_stream.next() => {
                let signal = match signal_opt {
                    Some(s) => s,
                    None => {
                        log_debug(debug, "VerifyStatus stream closed");
                        break FprintOutcome::DeviceError;
                    }
                };

                let args = match signal.args() {
                    Ok(a) => a,
                    Err(e) => {
                        log_debug(debug, &format!("Failed to parse signal args: {}", e));
                        continue;
                    }
                };

                log_debug(
                    debug,
                    &format!("fprintd status: result='{}', done={}", args.result, args.done),
                );

                match args.result {
                    "verify-match" => {
                        log_debug(debug, "Fingerprint matched successfully!");
                        break FprintOutcome::Matched;
                    }
                    "verify-no-match" => {
                        tries += 1;
                        log_debug(debug, &format!("Fingerprint mismatch (attempt {}/{})", tries, max_tries));
                        if tries >= max_tries || args.done {
                            break FprintOutcome::ExceededTries;
                        }
                    }
                    _ => {
                        // Intermediate state (retry scan, swipe too short, etc.)
                        if args.done {
                            tries += 1;
                            if tries >= max_tries {
                                break FprintOutcome::ExceededTries;
                            }
                            // If done was true, re-arm verify_start for remaining tries
                            let mut rearmed = false;
                            for _ in 0..3 {
                                match device.verify_start("any").await {
                                    Ok(()) => {
                                        rearmed = true;
                                        break;
                                    }
                                    Err(e) if is_device_busy_error(&e) => {
                                        sleep(Duration::from_millis(100)).await;
                                    }
                                    Err(_) => break,
                                }
                            }
                            if !rearmed {
                                log_debug(debug, "Failed to re-arm verify_start after intermediate state");
                                break FprintOutcome::DeviceError;
                            }
                        }
                    }
                }
            }
        }
    };

    if claimed {
        log_debug(debug, "Stopping fprint verification and releasing device");
        let _ = device.verify_stop().await;
        let _ = device.release().await;
    }

    outcome
}

/// Returns true if the D-Bus error indicates that the fingerprint device is
/// currently busy with another operation or claimed by another process.
pub fn is_device_busy_error(err: &zbus::Error) -> bool {
    if let zbus::Error::MethodError(name, desc, _) = err {
        let name_str = name.as_str();
        if name_str == "net.reactivated.Fprint.Error.AlreadyInUse"
            || name_str == "net.reactivated.Fprint.Error.ClaimDevice"
            || name_str == "net.reactivated.Fprint.Error.DeviceBusy"
            || name_str.ends_with(".AlreadyInUse")
            || name_str.ends_with(".ClaimDevice")
            || name_str.ends_with(".DeviceBusy")
        {
            return true;
        }
        if let Some(msg) = desc {
            let msg_lower = msg.to_lowercase();
            if msg_lower.contains("already")
                || msg_lower.contains("busy")
                || msg_lower.contains("in use")
                || msg_lower.contains("in-use")
                || msg_lower.contains("already open")
                || msg_lower.contains("already claimed")
            {
                return true;
            }
        }
    }

    let err_str = err.to_string().to_lowercase();
    err_str.contains("alreadyinuse")
        || err_str.contains("devicebusy")
        || err_str.contains("already claimed")
        || err_str.contains("already open")
        || err_str.contains("already being used")
        || err_str.contains("device is busy")
        || err_str.contains("busy with another")
        || err_str.contains("in use")
        || err_str.contains("device was not claimed before use")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_message() -> zbus::message::Message {
        zbus::message::Message::method_call("/test", "test")
            .build(&())
            .unwrap()
    }

    #[test]
    fn test_is_device_busy_error_matching() {
        let err_already_in_use = zbus::Error::MethodError(
            zbus::names::ErrorName::try_from("net.reactivated.Fprint.Error.AlreadyInUse")
                .unwrap()
                .into(),
            Some("Device was already claimed".to_string()),
            dummy_message(),
        );
        assert!(is_device_busy_error(&err_already_in_use));

        let err_claim_device = zbus::Error::MethodError(
            zbus::names::ErrorName::try_from("net.reactivated.Fprint.Error.ClaimDevice")
                .unwrap()
                .into(),
            Some("Device was already open".to_string()),
            dummy_message(),
        );
        assert!(is_device_busy_error(&err_claim_device));

        let err_device_busy = zbus::Error::MethodError(
            zbus::names::ErrorName::try_from("net.reactivated.Fprint.Error.DeviceBusy")
                .unwrap()
                .into(),
            Some("Device is busy with another request".to_string()),
            dummy_message(),
        );
        assert!(is_device_busy_error(&err_device_busy));

        let err_generic_string = zbus::Error::Failure(
            "net.reactivated.Fprint.Error.AlreadyInUse: Device was already claimed".to_string(),
        );
        assert!(is_device_busy_error(&err_generic_string));

        // Negative test cases
        let err_perm_denied = zbus::Error::MethodError(
            zbus::names::ErrorName::try_from("net.reactivated.Fprint.Error.PermissionDenied")
                .unwrap()
                .into(),
            Some("Not authorized".to_string()),
            dummy_message(),
        );
        assert!(!is_device_busy_error(&err_perm_denied));

        let err_no_prints = zbus::Error::MethodError(
            zbus::names::ErrorName::try_from("net.reactivated.Fprint.Error.NoEnrolledPrints")
                .unwrap()
                .into(),
            Some("No enrolled fingers found".to_string()),
            dummy_message(),
        );
        assert!(!is_device_busy_error(&err_no_prints));
    }
}
