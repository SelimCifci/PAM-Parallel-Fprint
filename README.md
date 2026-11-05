# Parallel-fprint

A Linux PAM module written in Rust that enables concurrent password and fingerprint authentication.

Instead of sequentially blocking on a fingerprint scan before prompting for a password (or vice-versa), `parallel_fprint` prompts for your password while simultaneously listening for fingerprint sensor events via `fprintd` over D-Bus. Whichever method validates first authenticates the session immediately.

---

## Features

- **True Concurrency**: Simultaneously races the PAM conversation (`pam_conv`) password prompt against asynchronous D-Bus signals from `net.reactivated.Fprint`.
- **Fast Bypass (`PAM_IGNORE`)**: If no fingerprint reader is detected on the system or the authenticating user has no fingerprints enrolled, the module bypasses immediately without prompting, passing transparently to the next module in the PAM stack.
- **Terminal & TTY Safety**: Saves and restores terminal attributes (`termios`), safely interrupts blocking prompts on TTY or GUI environments using synthetic newline injection (`TIOCSTI`) and non-restartable signals (`SIGUSR1`), and guarantees terminal echo is never left disabled.
- **Pass-through Integration**: When password authentication is used, stores the token in `PAM_AUTHTOK` and returns `PAM_IGNORE` so subsequent modules like `pam_unix.so try_first_pass` verify the credentials without re-prompting.
- **Clean Hardware Lifecycle**: Guarantees that `VerifyStop()` and `Release()` are invoked on `fprintd` under all exit conditions (password submitted, max tries exceeded, timeout, or cancellation).

---

## Configuration Options

Options can be appended to the module configuration line in `/etc/pam.d/`:

| Option | Description | Default |
| :--- | :--- | :--- |
| `debug` | Logs detailed diagnostic messages to syslog (`LOG_AUTHPRIV`). | Off |
| `prompt="<text>"` | Customizes the password prompt text. | `"Password or fingerprint: "` |
| `max_tries=<N>` | Max failed fingerprint attempts before discontinuing sensor checks and waiting solely for password. | `3` |
| `timeout=<N>` | Timeout in seconds for fingerprint verification. | `30` |

---

## PAM Configuration Example

In your PAM service file (for example `/etc/pam.d/sudo` or `/etc/pam.d/system-auth`):

```pam
# 1. Parallel fingerprint and password prompt
auth        sufficient    pam_parallel_fprint.so debug prompt="Password or fingerprint: "

# 2. Standard unix password check (uses the token provided by pam_parallel_fprint)
auth        sufficient    pam_unix.so try_first_pass nullok

# 3. Fallback denied
auth        required      pam_deny.so
```

---

## Isolated Testing (Without risking sudo lockouts)

You can test the module safely using a dedicated PAM service configuration:

1. Create a test PAM service `/etc/pam.d/parallel-fprint-test`:
   ```pam
   auth sufficient /path/to/Parallel-fprint/target/release/libparallel_fprint.so debug
   auth sufficient pam_unix.so try_first_pass nullok
   auth required   pam_deny.so
   ```

2. Run the included test runner:
   ```bash
   cargo run --example pam_runner -- parallel-fprint-test $USER
   ```

---

## Building & Installing

### Automated System Installation (Recommended)

You can build and install directly to `/lib/security/` using the custom cargo xtask runner:

```bash
cargo install-pam
# or: cargo xtask install
# or: make install
```

This task will:
1. Automatically compile the shared library in `--release` mode.
2. Install `libparallel_fprint.so` into `/lib/security/` (and `/usr/lib/security/`).
3. Set the correct file permissions (`0755` / `rwxr-xr-x`).

You can also inspect or uninstall:
```bash
cargo xtask status       # Check current installation status and permissions
cargo xtask uninstall    # Remove the PAM module from system directories
```

---

## Manual Building

Build the shared library manually:
```bash
cargo build --release
```
The resulting shared object will be located at:
```text
target/release/libparallel_fprint.so
```

