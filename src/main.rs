use std::ffi::c_void;

use windows::{
    core::PCSTR,
    s,
    Win32::{
        Foundation::HWND,
        System::{
            Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
            LibraryLoader::{GetProcAddress, LoadLibraryA},
            Threading::GetCurrentProcess,
        },
        UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_RESULT, MESSAGEBOX_STYLE},
    },
};

static mut MESSAGE_BOX_ORIGINAL_BYTES: [u8; 6] = [0; 6];
static mut BYTES_WRITTEN: usize = 0;
static mut MESSAGE_BOX_ADDRESS: Option<unsafe extern "system" fn() -> isize> = None;

#[no_mangle]
pub extern "stdcall" fn HookedMessageBox(
    hwnd: HWND,
    mut lptext: PCSTR,
    mut lpcaption: PCSTR,
    utype: MESSAGEBOX_STYLE,
) -> MESSAGEBOX_RESULT {
    unsafe {
        // Print intercepted values from the MessageBoxA function
        println!(
            "================\nHooked!!!\noriginal-lptext: {}\noriginal-lpcation: {}\n================",
            lptext.to_string().unwrap(),
            lpcaption.to_string().unwrap(),
        );

        // Change intercepted values from the MessageBoxA function
        lptext = s!("Hooked Hello World");
        lpcaption = s!("Hooked Rust");

        // Print new values from the MessageBoxA function
        println!(
            "\n================\nHooked!!!\nhooked-lptext: {}\nhooked-lpcation: {}\n================",
            lptext.to_string().unwrap(),
            lpcaption.to_string().unwrap(),
        );

        // Unpatch MessageBoxA
        WriteProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            MESSAGE_BOX_ORIGINAL_BYTES.as_ptr().cast::<c_void>(),
            6,
            Some(BYTES_WRITTEN as *mut usize),
        );

        // call the original MessageBoxA
        MessageBoxA(hwnd, lptext, lpcaption, utype)
    }
}

fn main() {
    unsafe {
        // Show messagebox before hooking
        MessageBoxA(HWND(0), s!("Hello World"), s!("Rust"), Default::default());

        let dll_handle = LoadLibraryA(s!("user32.dll")).unwrap();
        let bytes_read: usize = 0;

        // Get address of the MessageBox function in memory
        MESSAGE_BOX_ADDRESS = GetProcAddress(dll_handle, s!("MessageBoxA"));

        // save the first 6 bytes of the original MessageBoxA function - will need for unhooking
        ReadProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            MESSAGE_BOX_ORIGINAL_BYTES.as_ptr() as *mut c_void,
            6,
            Some(bytes_read as *mut usize),
        );

        // Create a patch "push <address of new MessageBoxA); ret"
        let hooked_message_box_address = (HookedMessageBox as *mut ()).cast::<c_void>();
        let offset = hooked_message_box_address as isize;

        let mut patch = [0; 6];
        patch[0] = 0x68;

        let temp = offset.to_ne_bytes();

        patch[1..5].copy_from_slice(&temp[..4]);
        patch[5] = 0xC3;

        // Patch the MessageBoxA
        WriteProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            patch.as_ptr().cast::<c_void>(),
            6,
            Some(BYTES_WRITTEN as *mut usize),
        );

        // show messagebox after hooking
        MessageBoxA(HWND(0), s!("Hello World"), s!("Rust"), Default::default());
    }
}

// cargo +stable-i686-pc-windows-msvc run

/*
use std::ffi::c_void;

use windows::core::PCSTR;
use windows::s;
use windows::Win32::{
    Foundation::{HANDLE, HWND},
    System::{
        Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory},
        LibraryLoader::{GetProcAddress, LoadLibraryA},
        Threading::GetCurrentProcess,
    },
    UI::WindowsAndMessaging::{MessageBoxA, MESSAGEBOX_STYLE},
};

#[no_mangle]
pub fn HookedMessageBox(hwnd: isize, lptext: *const u8, lpcaption: *const u8, utype: u32) -> i32 {
    unsafe {
        WriteProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            MESSAGE_BOX_ORIGINAL_BYTES.as_ptr().cast::<c_void>(),
            5,
            None,
        );

        println!(
            "lptext: {}\nlpcation: {}",
            PCSTR(lptext).to_string().unwrap(),
            PCSTR(lpcaption).to_string().unwrap(),
        );

        std::thread::sleep(std::time::Duration::from_secs(3));

        MessageBoxA(
            HWND(hwnd),
            PCSTR(lptext),
            PCSTR(lpcaption),
            MESSAGEBOX_STYLE(utype),
        )
        .0
    }
}

static mut MESSAGE_BOX_ORIGINAL_BYTES: [u8; 5] = [0; 5];
static mut MESSAGE_BOX_ADDRESS: Option<unsafe extern "system" fn() -> isize> = None;

fn main() {
    unsafe {
        let dll_handle = LoadLibraryA(s!("user32.dll")).unwrap();
        MESSAGE_BOX_ADDRESS = GetProcAddress(dll_handle, s!("MessageBoxA"));

        MESSAGE_BOX_ORIGINAL_BYTES = [0; 5];

        ReadProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            MESSAGE_BOX_ORIGINAL_BYTES.as_ptr() as *mut c_void,
            5,
            None,
        );

        let hooked_func_address = (HookedMessageBox as *mut ()).cast::<c_void>();

        let offset = hooked_func_address as isize - (MESSAGE_BOX_ADDRESS.unwrap() as isize + 5);

        let mut patch = [0; 5];
        patch[0] = 0xe9;

        let temp = offset.to_ne_bytes();

        /*
        for i in 1..patch.len() {
            patch[i] = temp[i - 1];
        }
        */
        patch[1..].copy_from_slice(&temp[..4]);

        WriteProcessMemory(
            GetCurrentProcess(),
            MESSAGE_BOX_ADDRESS.unwrap() as *const c_void,
            patch.as_ptr().cast::<c_void>(),
            5,
            None,
        );

        let runner = std::mem::transmute::<*mut c_void, fn(isize, *const u8, *const u8, u32) -> i32>(
            MESSAGE_BOX_ADDRESS.unwrap() as *mut c_void,
        );

        runner(
            0,
            "Hello World\0".as_ptr().cast::<u8>(),
            "Hello World\0".as_ptr().cast::<u8>(),
            0,
        );
    }
}
*/
