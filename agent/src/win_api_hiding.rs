#![cfg(target_os = "windows")]

use std::ffi::CString;
use std::os::raw::c_char; // Keep for LoadLibraryA cast, though LPCSTR is *const i8
use std::ptr;
use std::sync::OnceLock;

use obfstr::obfstr;
use winapi::shared::minwindef::{BOOL, DWORD, HMODULE};
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};
use winapi::um::winuser::LASTINPUTINFO; // Keep for struct definition
                                        // Removed: GetForegroundWindow, GetWindowTextW, OpenInputDesktop from winapi::um::winuser
                                        // Removed: WTSQuerySessionInformationW from winapi::um::wtsapi32
use winapi::shared::ntdef::LPWSTR;

use once_cell::sync::Lazy;

// Define function pointer types
type FnGetLastInputInfo = unsafe extern "system" fn(plii: *mut LASTINPUTINFO) -> BOOL;
type FnGetForegroundWindow = unsafe extern "system" fn() -> winapi::shared::windef::HWND;
type FnGetWindowTextW = unsafe extern "system" fn(
    hWnd: winapi::shared::windef::HWND,
    lpString: LPWSTR,
    nMaxCount: i32,
) -> i32;
type FnOpenInputDesktop = unsafe extern "system" fn(
    dwFlags: DWORD,
    fInherit: BOOL,
    dwDesiredAccess: DWORD,
) -> winapi::shared::windef::HDESK;
type FnWTSQuerySessionInformationW = unsafe extern "system" fn(
    hServer: winapi::shared::ntdef::HANDLE,
    SessionId: DWORD,
    WTSInfoClass: DWORD,
    ppBuffer: *mut LPWSTR,
    pBytesReturned: *mut DWORD,
) -> BOOL;

// Struct to hold resolved function pointers
#[derive(Debug)]
struct WinApiProcs {
    user32: HMODULE,
    wtsapi32: HMODULE,
    get_last_input_info: Option<FnGetLastInputInfo>,
    get_foreground_window: Option<FnGetForegroundWindow>,
    get_window_text_w: Option<FnGetWindowTextW>,
    open_input_desktop: Option<FnOpenInputDesktop>,
    wts_query_session_information_w: Option<FnWTSQuerySessionInformationW>,
}

unsafe impl Send for WinApiProcs {}
unsafe impl Sync for WinApiProcs {}

// Lazy static initializer for the API pointers
static API: OnceLock<WinApiProcs> = OnceLock::new();

impl WinApiProcs {
    fn get_proc<T>(module: HMODULE, name_bytes: &'static [u8]) -> Option<T> {
        let len_without_null = name_bytes
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(name_bytes.len());
        let name_slice_without_null = &name_bytes[0..len_without_null];

        let c_name = match CString::new(name_slice_without_null) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "[ERROR] Failed to create CString for API proc from bytes: {:?}, error: {}",
                    name_bytes, e
                );
                return None;
            }
        };

        let proc_addr = unsafe { GetProcAddress(module, c_name.as_ptr()) };
        if proc_addr.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute_copy(&proc_addr) })
        }
    }

    fn init() -> Self {
        unsafe {
            let user32_lib_name_str = obfstr!("USER32.DLL").to_string();
            let user32_lib_cstring = CString::new(user32_lib_name_str).unwrap();
            let user32 = LoadLibraryA(user32_lib_cstring.as_ptr() as *const c_char);

            let wtsapi32_lib_name_str = obfstr!("WTSAPI32.DLL").to_string();
            let wtsapi32_lib_cstring = CString::new(wtsapi32_lib_name_str).unwrap();
            let wtsapi32 = LoadLibraryA(wtsapi32_lib_cstring.as_ptr() as *const c_char);

            // Use static instead of const for obfstr!
            static GET_LAST_INPUT_INFO_BYTES_STORAGE: Lazy<Vec<u8>> =
                Lazy::new(|| obfstr!("GetLastInputInfo\0").as_bytes().to_vec());
            static GET_FOREGROUND_WINDOW_BYTES_STORAGE: Lazy<Vec<u8>> =
                Lazy::new(|| obfstr!("GetForegroundWindow\0").as_bytes().to_vec());
            static GET_WINDOW_TEXT_W_BYTES_STORAGE: Lazy<Vec<u8>> =
                Lazy::new(|| obfstr!("GetWindowTextW\0").as_bytes().to_vec());
            static OPEN_INPUT_DESKTOP_BYTES_STORAGE: Lazy<Vec<u8>> =
                Lazy::new(|| obfstr!("OpenInputDesktop\0").as_bytes().to_vec());
            static WTS_QUERY_SESSION_INFO_W_BYTES_STORAGE: Lazy<Vec<u8>> =
                Lazy::new(|| obfstr!("WTSQuerySessionInformationW\0").as_bytes().to_vec());

            WinApiProcs {
                user32,
                wtsapi32,
                get_last_input_info: if !user32.is_null() {
                    Self::get_proc(user32, &GET_LAST_INPUT_INFO_BYTES_STORAGE)
                } else {
                    None
                },
                get_foreground_window: if !user32.is_null() {
                    Self::get_proc(user32, &GET_FOREGROUND_WINDOW_BYTES_STORAGE)
                } else {
                    None
                },
                get_window_text_w: if !user32.is_null() {
                    Self::get_proc(user32, &GET_WINDOW_TEXT_W_BYTES_STORAGE)
                } else {
                    None
                },
                open_input_desktop: if !user32.is_null() {
                    Self::get_proc(user32, &OPEN_INPUT_DESKTOP_BYTES_STORAGE)
                } else {
                    None
                },
                wts_query_session_information_w: if !wtsapi32.is_null() {
                    Self::get_proc(wtsapi32, &WTS_QUERY_SESSION_INFO_W_BYTES_STORAGE)
                } else {
                    None
                },
            }
        }
    }
}

fn get_api() -> &'static WinApiProcs {
    API.get_or_init(WinApiProcs::init)
}

// Wrapper functions
pub unsafe fn get_last_input_info(plii: *mut LASTINPUTINFO) -> BOOL {
    if let Some(func) = get_api().get_last_input_info {
        func(plii)
    } else {
        0 // Indicate failure (BOOL is i32)
    }
}

pub unsafe fn get_foreground_window() -> winapi::shared::windef::HWND {
    if let Some(func) = get_api().get_foreground_window {
        func()
    } else {
        ptr::null_mut()
    }
}

pub unsafe fn get_window_text_w(
    hWnd: winapi::shared::windef::HWND,
    lpString: LPWSTR,
    nMaxCount: i32,
) -> i32 {
    if let Some(func) = get_api().get_window_text_w {
        func(hWnd, lpString, nMaxCount)
    } else {
        0 // Indicate failure
    }
}

pub unsafe fn open_input_desktop(
    dwFlags: DWORD,
    fInherit: BOOL,
    dwDesiredAccess: DWORD,
) -> winapi::shared::windef::HDESK {
    if let Some(func) = get_api().open_input_desktop {
        func(dwFlags, fInherit, dwDesiredAccess)
    } else {
        ptr::null_mut()
    }
}

pub unsafe fn wts_query_session_information_w(
    hServer: winapi::shared::ntdef::HANDLE,
    SessionId: DWORD,
    WTSInfoClass: DWORD,
    ppBuffer: *mut LPWSTR,
    pBytesReturned: *mut DWORD,
) -> BOOL {
    if let Some(func) = get_api().wts_query_session_information_w {
        func(hServer, SessionId, WTSInfoClass, ppBuffer, pBytesReturned)
    } else {
        0 // Indicate failure
    }
}

// Optional: Add a function to check if core APIs were resolved, for graceful degradation or error logging.
pub fn ensure_apis_loaded() -> bool {
    let api = get_api();
    // Check a few critical ones
    !api.user32.is_null()
        && !api.wtsapi32.is_null()
        && api.get_last_input_info.is_some()
        && api.get_foreground_window.is_some()
}
