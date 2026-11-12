use std::ffi::CString;

fn syslog_write(priority: libc::c_int, msg: &str) {
    if let Ok(c_msg) = CString::new(format!("pam_parallel_fprint: {msg}")) {
        unsafe {
            libc::openlog(
                c"pam_parallel_fprint".as_ptr(),
                libc::LOG_PID,
                libc::LOG_AUTHPRIV,
            );
            libc::syslog(priority, c"%s".as_ptr(), c_msg.as_ptr());
            libc::closelog();
        }
    }
}

pub fn log_debug(enabled: bool, msg: &str) {
    if enabled {
        syslog_write(libc::LOG_DEBUG, msg);
    }
}

pub fn log_err(msg: &str) {
    syslog_write(libc::LOG_ERR, msg);
}
