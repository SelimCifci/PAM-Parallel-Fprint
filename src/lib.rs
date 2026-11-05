pub mod auth;
pub mod config;
pub mod conv;
pub mod dbus;
pub mod log;

use pam::export_pam_module;
use pam::module::PamModule;
use pam::{PamHandle, PamReturnCode};
use std::ffi::CStr;
use std::os::raw::c_uint;

pub struct ParallelFprint;

impl PamModule for ParallelFprint {
    fn authenticate(handle: &PamHandle, args: Vec<&CStr>, flags: c_uint) -> PamReturnCode {
        auth::authenticate_impl(handle, &args, flags)
    }

    fn set_credentials(_handle: &PamHandle, _args: Vec<&CStr>, _flags: c_uint) -> PamReturnCode {
        PamReturnCode::Success
    }
}

export_pam_module!(ParallelFprint);
