use std::ffi::{CStr, CString};
use std::sync::mpsc;

use crate::log::log_debug;

#[derive(Debug)]
pub enum PromptResult {
    Password(Vec<u8>),
    Cancelled,
    Error,
}

pub struct TtyState {
    fd: libc::c_int,
    termios: libc::termios,
    is_tty: bool,
}

impl TtyState {
    pub fn save() -> Self {
        unsafe {
            let mut fd = 0;
            let mut is_tty = libc::isatty(fd) == 1;
            if !is_tty {
                let tty_fd = libc::open(c"/dev/tty".as_ptr(), libc::O_RDWR);
                if tty_fd >= 0 {
                    fd = tty_fd;
                    is_tty = true;
                }
            }

            let mut termios: libc::termios = std::mem::zeroed();
            if is_tty {
                let rc = libc::tcgetattr(fd, &mut termios);
                if rc != 0 {
                    is_tty = false;
                }
            }

            Self {
                fd,
                termios,
                is_tty,
            }
        }
    }

    pub fn restore(&self) {
        if self.is_tty {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.termios);
            }
        }
    }

    pub fn print_newline(&self) {
        if self.is_tty {
            unsafe {
                let nl = c"\n";
                let _ = libc::write(self.fd, nl.as_ptr() as *const libc::c_void, 1);
            }
        }
    }
}

impl Drop for TtyState {
    fn drop(&mut self) {
        if self.fd > 2 {
            unsafe {
                libc::close(self.fd);
            }
        }
    }
}

struct PromptContext {
    conv_ptr: *const pam::ffi::pam_conv,
    prompt: CString,
    sender: mpsc::Sender<PromptResult>,
}

extern "C" fn prompt_worker_c(arg: *mut libc::c_void) -> *mut libc::c_void {
    let ctx = unsafe { Box::from_raw(arg as *mut PromptContext) };
    let conv = unsafe { &*ctx.conv_ptr };
    if let Some(conv_fn) = conv.conv {
        let msg = pam::ffi::pam_message {
            msg_style: pam::ffi::PAM_PROMPT_ECHO_OFF,
            msg: ctx.prompt.as_ptr(),
        };
        let msg_ptr = &msg as *const pam::ffi::pam_message;
        let mut resp_ptr: *mut pam::ffi::pam_response = std::ptr::null_mut();

        let rc = unsafe {
            conv_fn(
                1,
                &msg_ptr as *const *const pam::ffi::pam_message
                    as *mut *const pam::ffi::pam_message,
                &mut resp_ptr,
                conv.appdata_ptr,
            )
        };

        if rc == pam::ffi::PAM_SUCCESS && !resp_ptr.is_null() {
            let resp = unsafe { *resp_ptr };
            let result = if !resp.resp.is_null() {
                let bytes = unsafe { CStr::from_ptr(resp.resp) }.to_bytes().to_vec();
                PromptResult::Password(bytes)
            } else {
                PromptResult::Password(Vec::new())
            };

            // Securely free PAM response buffers
            unsafe {
                if !(*resp_ptr).resp.is_null() {
                    let len = libc::strlen((*resp_ptr).resp);
                    libc::memset((*resp_ptr).resp as *mut libc::c_void, 0, len);
                    libc::free((*resp_ptr).resp as *mut libc::c_void);
                }
                libc::free(resp_ptr as *mut libc::c_void);
            }

            let _ = ctx.sender.send(result);
        } else {
            let _ = ctx.sender.send(PromptResult::Error);
        }
    } else {
        let _ = ctx.sender.send(PromptResult::Error);
    }

    std::ptr::null_mut()
}

pub struct PromptHandle {
    pub rx: mpsc::Receiver<PromptResult>,
    pub tid: libc::pthread_t,
    pub tty_state: TtyState,
}

impl PromptHandle {
    pub fn cancel(mut self) {
        if self.tid != 0 {
            unsafe {
                libc::pthread_cancel(self.tid);
                let mut retval: *mut libc::c_void = std::ptr::null_mut();
                libc::pthread_join(self.tid, &mut retval);
            }
            self.tid = 0;
        }

        self.tty_state.print_newline();
        self.tty_state.restore();
    }
}

impl Drop for PromptHandle {
    fn drop(&mut self) {
        if self.tid != 0 {
            unsafe {
                let mut retval: *mut libc::c_void = std::ptr::null_mut();
                libc::pthread_join(self.tid, &mut retval);
            }
            self.tid = 0;
        }
    }
}

/// Spawns the PAM conversation in a dedicated POSIX thread that supports cancellation.
pub fn spawn_prompt_thread(
    conv_ptr: *const pam::ffi::pam_conv,
    prompt: String,
    debug: bool,
) -> Option<PromptHandle> {
    if conv_ptr.is_null() {
        log_debug(debug, "Conversation pointer is null");
        return None;
    }

    let tty_state = TtyState::save();
    let (sender, rx) = mpsc::channel();
    let prompt_cstr = CString::new(prompt).unwrap_or_else(|_| CString::new("Password: ").unwrap());

    let ctx = Box::new(PromptContext {
        conv_ptr,
        prompt: prompt_cstr,
        sender,
    });

    let mut tid: libc::pthread_t = 0;
    let rc = unsafe {
        libc::pthread_create(
            &mut tid,
            std::ptr::null(),
            prompt_worker_c,
            Box::into_raw(ctx) as *mut libc::c_void,
        )
    };

    if rc == 0 {
        Some(PromptHandle { rx, tid, tty_state })
    } else {
        log_debug(
            debug,
            &format!("Failed to spawn POSIX prompt thread: rc={}", rc),
        );
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_tty_state_save_and_restore() {
        let state = TtyState::save();
        state.restore();
    }

    unsafe extern "C" fn mock_blocking_conv(
        _num_msg: libc::c_int,
        _msg: *mut *const pam::ffi::pam_message,
        _resp: *mut *mut pam::ffi::pam_response,
        appdata_ptr: *mut libc::c_void,
    ) -> libc::c_int {
        let fd = appdata_ptr as usize as libc::c_int;
        let mut buf = [0u8; 1];
        unsafe {
            libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1);
        }
        pam::ffi::PAM_SUCCESS
    }

    unsafe extern "C" fn mock_successful_conv(
        _num_msg: libc::c_int,
        _msg: *mut *const pam::ffi::pam_message,
        resp: *mut *mut pam::ffi::pam_response,
        _appdata_ptr: *mut libc::c_void,
    ) -> libc::c_int {
        unsafe {
            let resp_ptr = libc::calloc(1, std::mem::size_of::<pam::ffi::pam_response>())
                as *mut pam::ffi::pam_response;
            (*resp_ptr).resp = libc::strdup(c"secret".as_ptr());
            (*resp_ptr).resp_retcode = 0;
            *resp = resp_ptr;
        }
        pam::ffi::PAM_SUCCESS
    }

    #[test]
    fn test_mock_conv_success() {
        let conv = pam::ffi::pam_conv {
            conv: Some(mock_successful_conv),
            appdata_ptr: std::ptr::null_mut(),
        };

        let handle = spawn_prompt_thread(&conv, "Password: ".to_string(), false).unwrap();
        let res = handle.rx.recv_timeout(Duration::from_millis(200)).unwrap();
        match res {
            PromptResult::Password(pwd) => assert_eq!(pwd, b"secret"),
            _ => panic!("Expected Password result"),
        }
    }

    #[test]
    fn test_mock_conv_cancel() {
        let (rx_pipe, tx_pipe) = unsafe {
            let mut fds = [0; 2];
            assert_eq!(libc::pipe(fds.as_mut_ptr()), 0);
            (fds[0], fds[1])
        };

        let conv = pam::ffi::pam_conv {
            conv: Some(mock_blocking_conv),
            appdata_ptr: rx_pipe as usize as *mut libc::c_void,
        };

        let handle = spawn_prompt_thread(&conv, "Password: ".to_string(), false).unwrap();
        std::thread::sleep(Duration::from_millis(30));

        // Now cancel it - should unblock immediately without hanging!
        handle.cancel();

        unsafe {
            libc::close(rx_pipe);
            libc::close(tx_pipe);
        }
    }
}
