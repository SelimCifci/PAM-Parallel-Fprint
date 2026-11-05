use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MODULE_NAME: &str = "libparallel_fprint.so";
const PRIMARY_DEST: &str = "/lib/security";
const SECONDARY_DEST: &str = "/usr/lib/security";

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(|s| s.as_str()).unwrap_or("install");

    match command {
        "install" => do_install(),
        "uninstall" => do_uninstall(),
        "status" => do_status(),
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("Unknown command: '{}'", other);
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!("Parallel-fprint xtask management tool\n");
    println!("Usage:");
    println!("  cargo xtask install      Build release and install to /lib/security");
    println!("  cargo install-pam        Alias for 'cargo xtask install'");
    println!("  cargo xtask status       Check installation status of the PAM module");
    println!("  cargo xtask uninstall    Remove PAM module from system directories");
}

fn do_install() {
    println!("=== Building Parallel-fprint (--release) ===");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let build_status = Command::new(&cargo)
        .args(["build", "--release", "--lib"])
        .status()
        .expect("Failed to run cargo build");

    if !build_status.success() {
        eprintln!("Build failed. Aborting installation.");
        std::process::exit(1);
    }

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env::current_dir().unwrap().to_string_lossy().to_string()),
    );
    let src_file = manifest_dir
        .join("target")
        .join("release")
        .join(MODULE_NAME);

    if !src_file.exists() {
        eprintln!("Error: Built artifact '{}' not found!", src_file.display());
        std::process::exit(1);
    }

    println!("\n=== Installing to System Security Directories ===");
    let is_root = unsafe { libc::geteuid() == 0 };

    let mut dest_dirs = vec![Path::new(PRIMARY_DEST)];
    let secondary = Path::new(SECONDARY_DEST);
    // If /usr/lib/security is not the same directory or symlink target as /lib/security, copy to both
    if secondary.exists() {
        let is_distinct = match (
            fs::canonicalize(PRIMARY_DEST),
            fs::canonicalize(SECONDARY_DEST),
        ) {
            (Ok(p1), Ok(p2)) => p1 != p2,
            _ => true,
        };
        if is_distinct {
            dest_dirs.push(secondary);
        }
    }

    for dest_dir in dest_dirs {
        let dest_file = dest_dir.join(MODULE_NAME);
        println!("Target: {}", dest_file.display());

        if is_root {
            if !dest_dir.exists() {
                let _ = fs::create_dir_all(dest_dir);
            }
            match fs::copy(&src_file, &dest_file) {
                Ok(_) => {
                    let mut perms = fs::metadata(&dest_file).unwrap().permissions();
                    perms.set_mode(0o755);
                    let _ = fs::set_permissions(&dest_file, perms);
                    println!("  ✔ Copied and set permissions (0755)");
                }
                Err(e) => {
                    eprintln!("  ✖ Failed to copy: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            // Run via sudo
            let status = Command::new("sudo")
                .args(["mkdir", "-p", &dest_dir.to_string_lossy()])
                .status();
            if let Ok(st) = status
                && !st.success()
            {
                eprintln!("  ✖ sudo mkdir failed");
                std::process::exit(1);
            }

            let status = Command::new("sudo")
                .args([
                    "install",
                    "-m",
                    "0755",
                    &src_file.to_string_lossy(),
                    &dest_file.to_string_lossy(),
                ])
                .status();

            match status {
                Ok(st) if st.success() => {
                    println!("  ✔ Installed via sudo with mode 0755");
                }
                Ok(st) => {
                    eprintln!("  ✖ sudo install failed with exit code: {:?}", st.code());
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("  ✖ Failed to invoke sudo: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }

    println!(
        "\n✔ Successfully installed {} to /lib/security/",
        MODULE_NAME
    );
}

fn do_uninstall() {
    println!("=== Uninstalling Parallel-fprint ===");
    let is_root = unsafe { libc::geteuid() == 0 };

    for dir_path in [PRIMARY_DEST, SECONDARY_DEST] {
        let file = Path::new(dir_path).join(MODULE_NAME);
        if file.exists() {
            println!("Removing {}...", file.display());
            if is_root {
                let _ = fs::remove_file(&file);
                println!("  ✔ Removed");
            } else {
                let st = Command::new("sudo")
                    .args(["rm", "-f", &file.to_string_lossy()])
                    .status();
                if let Ok(st) = st
                    && st.success()
                {
                    println!("  ✔ Removed via sudo");
                }
            }
        }
    }
}

fn do_status() {
    println!("=== Parallel-fprint Installation Status ===");
    for dir_path in [PRIMARY_DEST, SECONDARY_DEST] {
        let file = Path::new(dir_path).join(MODULE_NAME);
        if file.exists() {
            match fs::metadata(&file) {
                Ok(meta) => {
                    let mode = meta.permissions().mode();
                    let len = meta.len();
                    println!("✔ Found: {}", file.display());
                    println!(
                        "  Size:        {:.2} MB ({} bytes)",
                        len as f64 / 1_048_576.0,
                        len
                    );
                    println!("  Permissions: {:o} (octal)", mode & 0o777);
                }
                Err(e) => println!(
                    "? Found {} but error reading metadata: {}",
                    file.display(),
                    e
                ),
            }
        } else {
            println!("✖ Not found: {}", file.display());
        }
    }
}
