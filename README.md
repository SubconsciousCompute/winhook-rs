# winhook-rs

> Windows API hooking is one of the techniques used by AV/EDR solutions to determine if code is malicious. You can read
> some of my notes on bypassing EDRs by leveraging unhooking.
>
> A simple program that will work follows:
>
> 1. Get memory address of the `MessageBoxA` function
> 2. Read the first 6 bytes of the `MessageBoxA` - will need these bytes for unhooking the function
> 3. Create a `HookedMessageBox` function that will be executed when the original `MessageBoxA` is called
> 4. Get memory address of the `HookedMessageBox`
> 5. Patch / redirect `MessageBoxA` to `HookedMessageBox`
> 6. Call `MessageBoxA`. Code gets redirected to `HookedMessageBox`
> 7. `HookedMessageBox` executes its code, prints the supplied arguments, unhooks the `MessageBoxA` and transfers the
     code control to the actual `MessageBoxA`

## Running

We need to build for `32bit` systems:

1. `rustup default nightly-i686-pc-windows-msvc`
2. `cargo run --release`

## Output

![MessageBox popup](resources/original_popup.png)
```
================
Hooked!!!
original-lptext: Hello World
original-lpcation: Rust
================

================
Hooked!!!
hooked-lptext: Hooked Hello World
hooked-lpcation: Hooked Rust
================
```
![MessageBox popup](resources/hooked_popup.png)

