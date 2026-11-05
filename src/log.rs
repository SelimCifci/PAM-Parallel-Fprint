use std::ffi::CString;

pub fn log_debug(enabled: bool, msg: &str) {
    if !enabled {
        return;
    }
    if let Ok(c_msg) = CString::new(format!("pam_parallel_fprint: {}", msg)) {
        unsafe {
            libc::openlog(
                c"pam_parallel_fprint".as_ptr(),
                libc::LOG_PID,
                libc::LOG_AUTHPRIV,
            );
            libc::syslog(libc::LOG_DEBUG, c"%s".as_ptr(), c_msg.as_ptr());
            libc::closelog();
        }
    }
}

pub fn log_err(msg: &str) {
    if let Ok(c_msg) = CString::new(format!("pam_parallel_fprint: {}", msg)) {
        unsafe {
            libc::openlog(
                c"pam_parallel_fprint".as_ptr(),
                libc::LOG_PID,
                libc::LOG_AUTHPRIV,
            );
            libc::syslog(libc::LOG_ERR, c"%s".as_ptr(), c_msg.as_ptr());
            libc::closelog();
        }
    }
}
