//! Local 504 image observation harness; it grants no deployment or mount authority.
use contour_ingress::{DockerPolicy, ReceiverImageRequest, observe_receiver_image};
use serde::Deserialize;
use std::{
    io::{self, Read},
    path::PathBuf,
    time::{Duration, Instant},
};
const INPUT_LIMIT: u64 = 16_384;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    docker: PathBuf,
    docker_sha256: String,
    socket: PathBuf,
    docker_config: PathBuf,
    python: PathBuf,
    python_sha256: String,
    source_root: PathBuf,
    stage_root: PathBuf,
    image_sha256: String,
    architecture: Architecture,
    owner_sha256: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "lowercase")]
enum Architecture {
    Arm64,
    Amd64,
}
fn digest(text: &str) -> Result<[u8; 32], ()> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return Err(());
    }
    let mut result = [0u8; 32];
    for (i, item) in result.iter_mut().enumerate() {
        *item = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(result)
}
fn read_input() -> Result<Input, ()> {
    let mut bytes = Vec::new();
    io::stdin()
        .lock()
        .take(INPUT_LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() as u64 > INPUT_LIMIT {
        return Err(());
    }
    serde_json::from_slice(&bytes).map_err(|_| ())
}
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let input = read_input()?;
    let docker = DockerPolicy::new(
        &input.docker,
        &input.socket,
        &input.docker_config,
        digest(&input.docker_sha256)?,
    )
    .map_err(|_| ())?;
    let python_sha256 = digest(&input.python_sha256)?;
    let image = digest(&input.image_sha256)?;
    let owner = digest(&input.owner_sha256)?;
    let scripts = input.source_root.join("scripts");
    let stage = input.stage_root.join("receiver504-image-stage");
    let deadline = Instant::now() + Duration::from_secs(540);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ())?;
    runtime.block_on(async {
        let evidence = observe_receiver_image(ReceiverImageRequest {
            docker: &docker,
            python: &input.python,
            python_sha256,
            scripts_dir: &scripts,
            stage_path: &stage,
            image,
            arm64: matches!(input.architecture, Architecture::Arm64),
            owner,
            deadline,
        })
        .await
        .map_err(|_| ())?;
        evidence.reinspect(&docker).await.map_err(|_| ())
    })
}
fn main() {
    if run().is_ok() {
        println!("receiver504_image_observation=pass");
    } else {
        println!("receiver504_image_observation=fail");
        std::process::exit(1);
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_is_strict_and_architecture_is_closed() {
        assert_eq!(digest(&"ab".repeat(32)).unwrap(), [0xab; 32]);
        assert!(digest(&"AB".repeat(32)).is_err());
        assert!(digest("abcd").is_err());
        assert!(serde_json::from_str::<Architecture>("\"arm64\"").is_ok());
        assert!(serde_json::from_str::<Architecture>("\"arm\"").is_err());
    }
    #[test]
    fn unknown_input_fields_are_rejected() {
        let text = format!(
            r#"{{"docker":"/d","docker_sha256":"{0}","socket":"/s","docker_config":"/c","python":"/p","python_sha256":"{0}","source_root":"/r","stage_root":"/t","image_sha256":"{0}","architecture":"arm64","owner_sha256":"{0}","recipe":"arbitrary"}}"#,
            "a".repeat(64)
        );
        assert!(serde_json::from_str::<Input>(&text).is_err());
    }
}
