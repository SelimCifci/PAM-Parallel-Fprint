use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const MODULE_NAME: &str = "libparallel_fprint.so";
const DEST_DIRS: [&str; 2] = ["/lib/security", "/usr/lib/security"];

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()).unwrap_or("install") {
        "install" => do_install(),
        "uninstall" => do_uninstall(),
        "status" => do_status(),
        "help" | "--help" | "-h" => print_help(),
        other => {
            eprintln!("Unknown command: '{other}'");
            print_help();
            std::process::exit(1);
        }
    }
}

fn print_help() {
    println!(
        "Parallel-fprint xtask management tool\n\n\
        Usage:\n  \
        cargo xtask install      Build release and install to /lib/security\n  \
        cargo install-pam        Alias for 'cargo xtask install'\n  \
        cargo xtask status       Check installation status of the PAM module\n  \
        cargo xtask uninstall    Remove PAM module from system directories"
    );
}

fn do_install() {
    println!("=== Building Parallel-fprint (--release) ===");
    let cargo = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    if !Command::new(&cargo)
        .args(["build", "--release", "--lib"])
        .status()
        .is_ok_and(|s| s.success())
    {
        eprintln!("Build failed. Aborting installation.");
        std::process::exit(1);
    }

    let manifest_dir = PathBuf::from(
        env::var("CARGO_MANIFEST_DIR")
            .unwrap_or_else(|_| env::current_dir().unwrap().to_string_lossy().to_string()),
    );
    let src_file = manifest_dir.join("target/release").join(MODULE_NAME);
    if !src_file.exists() {
        eprintln!("Error: Built artifact '{}' not found!", src_file.display());
        std::process::exit(1);
    }

    println!("\n=== Installing to System Security Directories ===");
    let is_root = unsafe { libc::geteuid() == 0 };

    let mut target_dirs = vec![Path::new(DEST_DIRS[0])];
    if let (Ok(p1), Ok(p2)) = (
        fs::canonicalize(DEST_DIRS[0]),
        fs::canonicalize(DEST_DIRS[1]),
    ) && p1 != p2
    {
        target_dirs.push(Path::new(DEST_DIRS[1]));
    }

    for dir in target_dirs {
        let dest = dir.join(MODULE_NAME);
        println!("Target: {}", dest.display());

        if is_root {
            let _ = fs::create_dir_all(dir);
            if fs::copy(&src_file, &dest).is_err() {
                eprintln!("  ✖ Failed to copy to {}", dest.display());
                std::process::exit(1);
            }
            let _ = fs::set_permissions(&dest, fs::Permissions::from_mode(0o755));
            println!("  ✔ Copied and set permissions (0755)");
        } else {
            let dir_str = dir.to_string_lossy();
            let src_str = src_file.to_string_lossy();
            let dest_str = dest.to_string_lossy();

            let _ = Command::new("sudo")
                .args(["mkdir", "-p", &dir_str])
                .status();
            let ok = Command::new("sudo")
                .args(["install", "-m", "0755", &src_str, &dest_str])
                .status()
                .is_ok_and(|s| s.success());

            if ok {
                println!("  ✔ Installed via sudo with mode 0755");
            } else {
                eprintln!("  ✖ sudo install failed for {}", dest.display());
                std::process::exit(1);
            }
        }
    }

    println!("\n✔ Successfully installed {MODULE_NAME} to system security directories");
}

fn do_uninstall() {
    println!("=== Uninstalling Parallel-fprint ===");
    let is_root = unsafe { libc::geteuid() == 0 };

    for dir_path in DEST_DIRS {
        let file = Path::new(dir_path).join(MODULE_NAME);
        if file.exists() {
            println!("Removing {}...", file.display());
            let ok = if is_root {
                fs::remove_file(&file).is_ok()
            } else {
                Command::new("sudo")
                    .args(["rm", "-f", &file.to_string_lossy()])
                    .status()
                    .is_ok_and(|s| s.success())
            };
            if ok {
                println!("  ✔ Removed");
            }
        }
    }
}

fn do_status() {
    println!("=== Parallel-fprint Installation Status ===");
    for dir in DEST_DIRS {
        let file = Path::new(dir).join(MODULE_NAME);
        if let Ok(meta) = fs::metadata(&file) {
            println!("✔ Found: {}", file.display());
            println!(
                "  Size:        {:.2} MB ({} bytes)",
                meta.len() as f64 / 1_048_576.0,
                meta.len()
            );
            println!(
                "  Permissions: {:o} (octal)",
                meta.permissions().mode() & 0o777
            );
        } else {
            println!("✖ Not found: {}", file.display());
        }
    }
}
