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
pub async fn check_device_and_prints(
    username: &str,
    debug: bool,
) -> Option<(Connection, OwnedObjectPath)> {
    log_debug(debug, &format!("Checking fprintd for user '{username}'"));
    let conn = Connection::system().await.ok()?;
    let mgr = FprintManagerProxy::new(&conn).await.ok()?;
    let dev_path = mgr.get_default_device().await.ok()?;
    let dev = FprintDeviceProxy::builder(&conn)
        .path(&dev_path)
        .build()
        .await
        .ok()?;

    let mut fingers_res = dev.list_enrolled_fingers(username).await;
    for _ in 1..=3 {
        if fingers_res.as_ref().err().is_some_and(is_device_busy_error) {
            sleep(Duration::from_millis(200)).await;
            fingers_res = dev.list_enrolled_fingers(username).await;
        } else {
            break;
        }
    }

    match fingers_res {
        Ok(fingers) if !fingers.is_empty() => {
            log_debug(
                debug,
                &format!("User '{username}' has enrolled fingers: {fingers:?}"),
            );
            Some((conn, dev_path))
        }
        _ => {
            log_debug(debug, &format!("No enrolled fingers for user '{username}'"));
            None
        }
    }
}

async fn try_start_verify(dev: &FprintDeviceProxy<'_>) -> zbus::Result<()> {
    for _ in 0..3 {
        match dev.verify_start("any").await {
            Ok(()) => return Ok(()),
            Err(e) if is_device_busy_error(&e) => sleep(Duration::from_millis(100)).await,
            Err(e) => return Err(e),
        }
    }
    dev.verify_start("any").await
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
    let Ok(device) = FprintDeviceProxy::builder(connection)
        .path(device_path)
        .build()
        .await
    else {
        log_debug(debug, "Failed to build device proxy");
        return FprintOutcome::DeviceError;
    };

    let timeout_fut = sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout_fut);

    // 1. Acquire device claim and start verification with graceful retry on busy
    let mut status_stream = loop {
        log_debug(debug, "Claiming fingerprint device");
        if device.claim(username).await.is_ok() {
            if let Ok(stream) = device.receive_verify_status().await {
                log_debug(debug, "Starting fprint verification");
                if try_start_verify(&device).await.is_ok() {
                    break stream;
                }
            }
            let _ = device.release().await;
        }

        tokio::select! {
            _ = &mut cancel_rx => return FprintOutcome::Cancelled,
            _ = &mut timeout_fut => return FprintOutcome::TimedOut,
            _ = sleep(Duration::from_millis(250)) => {}
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
                let Some(signal) = signal_opt else {
                    log_debug(debug, "VerifyStatus stream closed");
                    break FprintOutcome::DeviceError;
                };

                let Ok(args) = signal.args() else { continue };
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
                        log_debug(debug, &format!("Fingerprint mismatch (attempt {tries}/{max_tries})"));
                        if tries >= max_tries || args.done {
                            break FprintOutcome::ExceededTries;
                        }
                    }
                    _ if args.done => {
                        tries += 1;
                        if tries >= max_tries {
                            break FprintOutcome::ExceededTries;
                        }
                        if try_start_verify(&device).await.is_err() {
                            log_debug(debug, "Failed to re-arm verify_start after intermediate state");
                            break FprintOutcome::DeviceError;
                        }
                    }
                    _ => {}
                }
            }
        }
    };

    log_debug(debug, "Stopping fprint verification and releasing device");
    let _ = device.verify_stop().await;
    let _ = device.release().await;

    outcome
}

/// Returns true if the D-Bus error indicates that the fingerprint device is
/// currently busy with another operation or claimed by another process.
pub fn is_device_busy_error(err: &zbus::Error) -> bool {
    let check_str = |s: &str| {
        let l = s.to_ascii_lowercase();
        l.contains("already") || l.contains("busy") || l.contains("in use") || l.contains("in-use")
    };

    match err {
        zbus::Error::MethodError(name, desc, _) => {
            let n = name.as_str();
            n.ends_with(".AlreadyInUse")
                || n.ends_with(".ClaimDevice")
                || n.ends_with(".DeviceBusy")
                || desc.as_deref().is_some_and(check_str)
        }
        _ => check_str(&err.to_string()),
    }
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
