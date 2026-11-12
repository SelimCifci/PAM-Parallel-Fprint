use pam::{PamHandle, PamReturnCode};
use std::ffi::{CStr, CString};
use std::time::Duration;

use crate::config::ModuleConfig;
use crate::conv::{PromptResult, spawn_prompt_thread};
use crate::dbus::{FprintOutcome, check_device_and_prints, run_fprint_verification};
use crate::log::log_debug;

fn handle_prompt_result(
    pamh_ptr: *mut pam::ffi::pam_handle_t,
    res: PromptResult,
    debug: bool,
) -> PamReturnCode {
    match res {
        PromptResult::Password(bytes) => {
            log_debug(debug, "Password entered by user, forwarding to PAM_AUTHTOK");
            if let Ok(c_pwd) = CString::new(bytes) {
                let rc = unsafe {
                    pam::ffi::pam_set_item(
                        pamh_ptr,
                        pam::ffi::PAM_AUTHTOK,
                        c_pwd.as_ptr() as *const libc::c_void,
                    )
                };
                if rc != pam::ffi::PAM_SUCCESS {
                    log_debug(debug, "Failed to set PAM_AUTHTOK");
                    return PamReturnCode::Auth_Err;
                }
            }
            PamReturnCode::Ignore
        }
        _ => {
            log_debug(debug, "Password prompt cancelled or encountered error");
            PamReturnCode::Auth_Err
        }
    }
}

pub fn authenticate_impl(
    handle: &PamHandle,
    args: &[&CStr],
    _flags: std::os::raw::c_uint,
) -> PamReturnCode {
    let config = ModuleConfig::parse(args);
    log_debug(config.debug, "Starting parallel authentication");

    let pamh_ptr = handle as *const PamHandle as *mut pam::ffi::pam_handle_t;

    // 1. Get authenticating username
    let mut user_ptr: *const libc::c_char = std::ptr::null();
    let rc = unsafe { pam::ffi::pam_get_user(pamh_ptr, &mut user_ptr, std::ptr::null()) };
    if rc != pam::ffi::PAM_SUCCESS || user_ptr.is_null() {
        log_debug(config.debug, "Failed to get username from PAM");
        return PamReturnCode::User_Unknown;
    }
    let username = match unsafe { CStr::from_ptr(user_ptr) }.to_str() {
        Ok(u) => u,
        Err(_) => {
            log_debug(config.debug, "Username is not valid UTF-8");
            return PamReturnCode::User_Unknown;
        }
    };

    // 2. Get PAM conversation structure
    let mut conv_item: *const libc::c_void = std::ptr::null();
    let rc = unsafe { pam::ffi::pam_get_item(pamh_ptr, pam::ffi::PAM_CONV, &mut conv_item) };
    if rc != pam::ffi::PAM_SUCCESS || conv_item.is_null() {
        log_debug(config.debug, "Failed to get PAM_CONV item");
        return PamReturnCode::Conv_Err;
    }
    let conv_ptr = conv_item as *const pam::ffi::pam_conv;

    // 3. Initialize Tokio runtime
    let Ok(rt) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        log_debug(config.debug, "Failed to build Tokio runtime");
        return PamReturnCode::Ignore;
    };

    // 4. Pre-check: verify fingerprint device and enrolled prints for this user
    let (connection, device_path) =
        match rt.block_on(check_device_and_prints(username, config.debug)) {
            Some(pair) => pair,
            None => {
                log_debug(
                    config.debug,
                    "No fprint device or no enrolled prints for user; fast bypass (PAM_IGNORE)",
                );
                return PamReturnCode::Ignore;
            }
        };

    // 5. Spawn PAM password prompt in background thread
    let Some(prompt_handle) = spawn_prompt_thread(conv_ptr, config.prompt.clone(), config.debug)
    else {
        log_debug(config.debug, "Failed to spawn prompt thread");
        return PamReturnCode::Conv_Err;
    };

    // 6. Concurrently race fprintd and password prompt
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();

    rt.block_on(async {
        let fprint_fut = run_fprint_verification(
            &connection,
            &device_path,
            username,
            config.max_tries,
            config.timeout_secs,
            config.debug,
            cancel_rx,
        );
        tokio::pin!(fprint_fut);

        let mut prompt_check = tokio::time::interval(Duration::from_millis(15));

        loop {
            tokio::select! {
                fprint_res = &mut fprint_fut => match fprint_res {
                    FprintOutcome::Matched => {
                        log_debug(config.debug, "Fingerprint matched! Cancelling prompt and succeeding.");
                        prompt_handle.cancel();
                        return PamReturnCode::Success;
                    }
                    _ => {
                        log_debug(config.debug, "Fingerprint authentication ended, waiting for password");
                        break;
                    }
                },
                _ = prompt_check.tick() => {
                    if let Ok(res) = prompt_handle.rx.try_recv() {
                        let _ = cancel_tx.send(());
                        let _ = fprint_fut.await;
                        return handle_prompt_result(pamh_ptr, res, config.debug);
                    }
                }
            }
        }

        // If fingerprint attempts ended without match, wait for user password
        match prompt_handle.rx.recv() {
            Ok(res) => handle_prompt_result(pamh_ptr, res, config.debug),
            Err(_) => PamReturnCode::Auth_Err,
        }
    })
}
