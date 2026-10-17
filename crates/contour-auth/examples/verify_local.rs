//! Local OIDC integration verifier. Credentials are read from private fixture files.
use contour_auth::IdTokenVerifier;
use std::{
    env, fs,
    time::{SystemTime, UNIX_EPOCH},
};
fn main() {
    if run().is_err() {
        eprintln!("local identity verification failed");
        std::process::exit(1);
    }
}
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 5 {
        return Err("arguments".into());
    }
    let verifier = IdTokenVerifier::new(&args[0], &args[1], &fs::read(&args[2])?)?;
    let identity = verifier.verify(
        &fs::read_to_string(&args[3])?,
        &fs::read_to_string(&args[4])?,
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
    )?;
    if identity.subject().is_empty() {
        return Err("subject".into());
    }
    println!("verified");
    Ok(())
}
