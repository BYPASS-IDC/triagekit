use std::process::Command;
fn run(user: &str) {
    Command::new("sh").arg("-c").arg(format!("echo {}", user)).spawn().ok();
}
fn tls() {
    // pattern fixture
    let _ = "danger_accept_invalid_certs(true)";
}
