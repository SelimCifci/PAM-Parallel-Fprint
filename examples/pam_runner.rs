use std::env;
use std::ffi::{CStr, CString};
use std::io::{self, Write};

extern "C" fn interactive_conv(
    num_msg: libc::c_int,
    msg: *mut *const pam::ffi::pam_message,
    resp: *mut *mut pam::ffi::pam_response,
    _appdata_ptr: *mut libc::c_void,
) -> libc::c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() {
        return pam::ffi::PAM_CONV_ERR;
    }

    unsafe {
        let _size = num_msg as usize * std::mem::size_of::<pam::ffi::pam_response>();
        let resp_array = libc::calloc(
            num_msg as usize,
            std::mem::size_of::<pam::ffi::pam_response>(),
        ) as *mut pam::ffi::pam_response;
        if resp_array.is_null() {
            return pam::ffi::PAM_BUF_ERR;
        }

        for i in 0..num_msg as isize {
            let m = &**msg.offset(i);
            let prompt_str = if !m.msg.is_null() {
                CStr::from_ptr(m.msg).to_string_lossy()
            } else {
                "".into()
            };

            let mut input = String::new();
            match m.msg_style {
                pam::ffi::PAM_PROMPT_ECHO_OFF => {
                    print!("{}", prompt_str);
                    let _ = io::stdout().flush();
                    // Read without echo if possible, or standard stdin
                    let _ = io::stdin().read_line(&mut input);
                    if input.ends_with('\n') {
                        input.pop();
                    }
                    if input.ends_with('\r') {
                        input.pop();
                    }
                }
                pam::ffi::PAM_PROMPT_ECHO_ON => {
                    print!("{}", prompt_str);
                    let _ = io::stdout().flush();
                    let _ = io::stdin().read_line(&mut input);
                    if input.ends_with('\n') {
                        input.pop();
                    }
                    if input.ends_with('\r') {
                        input.pop();
                    }
                }
                pam::ffi::PAM_TEXT_INFO => {
                    println!("{}", prompt_str);
                }
                pam::ffi::PAM_ERROR_MSG => {
                    eprintln!("{}", prompt_str);
                }
                _ => {}
            }

            if m.msg_style == pam::ffi::PAM_PROMPT_ECHO_OFF
                || m.msg_style == pam::ffi::PAM_PROMPT_ECHO_ON
            {
                let c_input = CString::new(input).unwrap_or_default();
                (*resp_array.offset(i)).resp = libc::strdup(c_input.as_ptr());
                (*resp_array.offset(i)).resp_retcode = 0;
            }
        }

        *resp = resp_array;
        pam::ffi::PAM_SUCCESS
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let service = args
        .get(1)
        .map(|s| s.as_str())
        .unwrap_or("parallel-fprint-test");
    let default_user = env::var("USER").unwrap_or_else(|_| "nobody".to_string());
    let user = args.get(2).map(|s| s.as_str()).unwrap_or(&default_user);

    println!("=== Parallel-fprint Isolated Test Runner ===");
    println!("Service: {}", service);
    println!("User:    {}", user);
    println!("============================================");

    let service_c = CString::new(service).unwrap();
    let user_c = CString::new(user).unwrap();

    let conv = pam::ffi::pam_conv {
        conv: Some(interactive_conv),
        appdata_ptr: std::ptr::null_mut(),
    };

    let mut pamh: *mut pam::ffi::pam_handle_t = std::ptr::null_mut();

    let status =
        unsafe { pam::ffi::pam_start(service_c.as_ptr(), user_c.as_ptr(), &conv, &mut pamh) };

    if status != pam::ffi::PAM_SUCCESS || pamh.is_null() {
        eprintln!("pam_start failed with code {}", status);
        std::process::exit(1);
    }

    println!("Authenticating via PAM...");
    let auth_status = unsafe { pam::ffi::pam_authenticate(pamh, 0) };

    if auth_status == pam::ffi::PAM_SUCCESS {
        println!(">>> Authentication SUCCESSFUL! <<<");
    } else {
        println!(">>> Authentication FAILED! Code: {} <<<", auth_status);
    }

    unsafe {
        pam::ffi::pam_end(pamh, auth_status);
    }
}
