use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEST_DIRECTORY_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn create_home_with_config(config: &str) -> PathBuf {
    let unique_id = TEST_DIRECTORY_COUNTER.fetch_add(1, Ordering::Relaxed);
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let home = std::env::temp_dir().join(format!(
        "digg-config-test-{}-{}-{}",
        std::process::id(),
        timestamp,
        unique_id
    ));

    fs::create_dir_all(&home).unwrap();
    fs::write(home.join(".diggrc"), config).unwrap();
    home
}

fn run_digg(home: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_digg"))
        .env("HOME", home)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn config_file_options_apply_before_and_yield_to_cli_options() {
    let home = create_home_with_config("+color\n");

    let configured = run_digg(&home, &["--help"]);
    assert!(configured.status.success());
    assert!(configured.stdout.contains(&0x1b));

    let overridden = run_digg(&home, &["+nocolor", "--help"]);
    assert!(overridden.status.success());
    assert!(!overridden.stdout.contains(&0x1b));

    fs::remove_dir_all(home).unwrap();
}
