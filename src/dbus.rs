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

    match device.list_enrolled_fingers(username).await {
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

    log_debug(debug, "Claiming fingerprint device");
    if let Err(e) = device.claim(username).await {
        log_debug(debug, &format!("Failed to claim fingerprint device: {}", e));
        return FprintOutcome::DeviceError;
    }

    log_debug(debug, "Starting fprint verification");
    if let Err(e) = device.verify_start("any").await {
        log_debug(debug, &format!("Failed to start verification: {}", e));
        let _ = device.release().await;
        return FprintOutcome::DeviceError;
    }

    let mut status_stream = match device.receive_verify_status().await {
        Ok(s) => s,
        Err(e) => {
            log_debug(
                debug,
                &format!("Failed to subscribe to verify status: {}", e),
            );
            let _ = device.verify_stop().await;
            let _ = device.release().await;
            return FprintOutcome::DeviceError;
        }
    };

    let mut tries = 0;
    let timeout_fut = sleep(Duration::from_secs(timeout_secs));
    tokio::pin!(timeout_fut);

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
                            let _ = device.verify_start("any").await;
                        }
                    }
                }
            }
        }
    };

    log_debug(debug, "Stopping fprint verification and releasing device");
    let _ = device.verify_stop().await;
    let _ = device.release().await;

    outcome
}
