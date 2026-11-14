//! Opt-in loopback TLS qualification. CID/owner values are synthetic data only.
use super::*;
use crate::{HttpLimits, ReceiverCausalConfig504, ReceiverCausalServer504, ReceiverRegistry504};
use contour_core::{CausalGrantKeys, PolicyKeys};
use contour_postgres::{DatabaseSettings, ReceiverEvidenceTls, TrustedCa};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder},
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant as WallInstant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::TlsConnector;
const LIMIT: Duration = Duration::from_secs(4);
struct Fixture {
    dir: PathBuf,
    openssl: PathBuf,
    stop: WallInstant,
}
impl Fixture {
    fn new() -> Self {
        let openssl = PathBuf::from(
            std::env::var_os("CONTOUR_TEST_OPENSSL").expect("explicit qualified OpenSSL path"),
        );
        assert!(
            openssl.is_absolute() && openssl.is_file(),
            "qualified OpenSSL executable required"
        );
        let openssl = openssl.canonicalize().expect("qualified OpenSSL path");
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "contour-receiver-tls-{}-{nonce}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&dir).expect("private fixture directory");
        let fixture = Self {
            dir,
            openssl,
            stop: WallInstant::now() + Duration::from_secs(55),
        };
        fs::write(
            fixture.dir.join("fixture.cnf"),
            "[req]\ndistinguished_name=dn\n[dn]\n",
        )
        .unwrap();
        fixture.ca("ca");
        fixture.ca("other");
        fixture.leaf("server", "ca", "serverAuth", true, "2");
        fixture.leaf("client", "ca", "clientAuth", false, "3");
        fixture.leaf("evidence", "ca", "clientAuth", false, "6");
        fixture.leaf("untrusted", "other", "clientAuth", false, "4");
        fixture.leaf("wrong-purpose", "ca", "serverAuth", false, "5");
        fixture.run(&[
            "dgst",
            "-sha256",
            "-binary",
            "-out",
            "client.sha256",
            "client.der",
        ]);
        fixture
    }
    fn run(&self, args: &[&str]) {
        let mut child = Command::new(&self.openssl)
            .args(args)
            .current_dir(&self.dir)
            .env_clear()
            .env("LC_ALL", "C")
            .env("OPENSSL_CONF", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("qualified synthetic OpenSSL command");
        let deadline = (WallInstant::now() + Duration::from_secs(15)).min(self.stop);
        loop {
            if let Some(status) = child.try_wait().expect("fixture process status") {
                assert!(status.success(), "synthetic OpenSSL command failed");
                return;
            }
            if WallInstant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("synthetic OpenSSL command deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn ca(&self, name: &str) {
        self.run(&[
            "req",
            "-config",
            "fixture.cnf",
            "-x509",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.pem"),
            "-days",
            "1",
            "-subj",
            "/CN=synthetic-ca",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        ]);
        self.run(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
    }
    fn leaf(&self, name: &str, ca: &str, purpose: &str, server: bool, serial: &str) {
        self.run(&[
            "req",
            "-config",
            "fixture.cnf",
            "-new",
            "-newkey",
            "ed25519",
            "-nodes",
            "-keyout",
            &format!("{name}.key"),
            "-out",
            &format!("{name}.csr"),
            "-subj",
            "/CN=synthetic-leaf",
        ]);
        let mut extension = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={purpose}\n"
        );
        if server {
            extension.push_str("subjectAltName=DNS:localhost\n");
        }
        fs::write(self.dir.join(format!("{name}.ext")), extension).unwrap();
        self.run(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.pem"),
            "-CAkey",
            &format!("{ca}.key"),
            "-set_serial",
            serial,
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
        self.run(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
        self.run(&[
            "pkcs8",
            "-topk8",
            "-nocrypt",
            "-in",
            &format!("{name}.key"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.key.der"),
        ]);
    }
    fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.dir.join(name)).unwrap()
    }
    fn server(&self) -> ReceiverEvidenceTls {
        ReceiverEvidenceTls::from_der(
            &[&self.read("server.der")],
            &self.read("server.key.der"),
            &[&self.read("ca.der")],
            LIMIT,
        )
        .unwrap()
    }
    fn client(
        &self,
        identity: Option<&str>,
        version: &'static rustls::SupportedProtocolVersion,
    ) -> Arc<ClientConfig> {
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.read("ca.der")))
            .unwrap();
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(roots);
        let mut config = match identity {
            Some(name) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from(self.read(&format!("{name}.der")))],
                    PrivateKeyDer::try_from(self.read(&format!("{name}.key.der"))).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        };
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.dir).expect("owned synthetic fixture cleanup");
    }
}

async fn send(
    addr: std::net::SocketAddr,
    client: Arc<ClientConfig>,
    wire: Vec<u8>,
) -> Result<Vec<u8>, ()> {
    timeout(LIMIT, async {
        let socket = TcpStream::connect(addr).await.map_err(|_| ())?;
        let mut stream = TlsConnector::from(client)
            .connect(
                ServerName::try_from("localhost")
                    .map_err(|_| ())?
                    .to_owned(),
                socket,
            )
            .await
            .map_err(|_| ())?;
        stream.write_all(&wire).await.map_err(|_| ())?;
        let mut output = Vec::new();
        stream.read_to_end(&mut output).await.map_err(|_| ())?;
        // A clean socket close without an HTTP response is a transport failure.
        if output.is_empty() || output.len() > 4096 {
            return Err(());
        }
        Ok(output)
    })
    .await
    .map_err(|_| ())?
}
fn wire(path: &str, media: &str, body: &[u8], extra: &str) -> Vec<u8> {
    let mut message=format!("POST {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n",body.len()).into_bytes();
    message.extend_from_slice(body);
    message
}
fn code(result: &Result<Vec<u8>, ()>, expected: u16) -> bool {
    result
        .as_ref()
        .is_ok_and(|bytes| bytes.starts_with(format!("HTTP/1.1 {expected} ").as_bytes()))
}
fn config(f: &Fixture) -> ReceiverCausalConfig504 {
    let key: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];
    let settings = || {
        DatabaseSettings::new(
            "localhost",
            1,
            "unused",
            "unused",
            b"unused",
            Duration::from_secs(1),
        )
        .unwrap()
    };
    let trust = || TrustedCa::from_pem(&f.read("ca.pem")).unwrap();
    ReceiverCausalConfig504 {
        tls: f.server(),
        registry: ReceiverRegistry504::pending_only(),
        event_database: settings(),
        event_trust: trust(),
        fact_database: settings(),
        fact_trust: trust(),
        grant_keys: CausalGrantKeys::new(&[("fixture", key)]).unwrap(),
        policy_keys: PolicyKeys::new(&[("fixture", key)]).unwrap(),
        limits: HttpLimits::new(16, LIMIT)
            .unwrap()
            .with_database_sessions(2)
            .unwrap(),
        event_slots: 1,
    }
}
#[test]
#[ignore = "requires explicit qualified OpenSSL binary"]
fn qualified_preauth_http_mtls_and_one_use() {
    let fixture = Fixture::new();
    let export_pin: [u8; 32] = Sha256::digest(fixture.read("client.der")).into();
    let evidence_pin: [u8; 32] = Sha256::digest(fixture.read("evidence.der")).into();
    assert_ne!(export_pin, evidence_pin);
    let client = fixture.client(Some("client"), &rustls::version::TLS13);
    let evidence = fixture.client(Some("evidence"), &rustls::version::TLS13);
    let untrusted = fixture.client(Some("untrusted"), &rustls::version::TLS13);
    let wrong_purpose = fixture.client(Some("wrong-purpose"), &rustls::version::TLS13);
    let missing = fixture.client(None, &rustls::version::TLS13);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            timeout(
                fixture.stop.saturating_duration_since(WallInstant::now()),
                async {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let (server, broker) =
                        ReceiverCausalServer504::new_with_preauth(config(&fixture)).unwrap();
                    let (stop, shutdown) = oneshot::channel::<()>();
                    let task = tokio::spawn(async move {
                        server
                            .serve(listener, async {
                                let _ = shutdown.await;
                            })
                            .await
                    });
                    let ready = Instant::now() + LIMIT;
                    while !broker.is_active() {
                        assert!(Instant::now() < ready);
                        tokio::task::yield_now().await;
                    }
                    let deadline = Instant::now() + Duration::from_secs(45);
                    let owner = [1; 32];
                    let cid = [2; 32];
                    let register = || broker.register(owner, cid, export_pin, deadline).unwrap();
                    let request =
                        |path: &str, body: &[u8]| wire(path, "application/octet-stream", body, "");
                    let ticket = register();
                    let token = ticket.challenge();
                    let res = send(
                        addr,
                        client.clone(),
                        request("/v1/receiver-preauth", token.as_bytes()),
                    )
                    .await;
                    assert!(code(&res, 200));
                    assert!(
                        ticket
                            .receive()
                            .await
                            .unwrap()
                            .consume(&broker, owner, cid, deadline)
                            .is_ok()
                    );
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    let ticket = register();
                    let token = ticket.challenge();
                    assert!(code(
                        &send(
                            addr,
                            evidence.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    assert!(ticket.receive().await.is_err());
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    let ticket = register();
                    let token = ticket.challenge();
                    for bad in [missing, untrusted, wrong_purpose] {
                        assert!(
                            send(addr, bad, request("/v1/receiver-preauth", token.as_bytes()))
                                .await
                                .is_err()
                        );
                    }
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request(
                                "/v1/receiver-preauth",
                                b"0000000000000000000000000000000000000000000000000000000000000000"
                            )
                        )
                        .await,
                        403
                    ));
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            wire(
                                "/v1/receiver-preauth",
                                "application/json",
                                token.as_bytes(),
                                ""
                            )
                        )
                        .await,
                        415
                    ));
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            wire(
                                "/v1/receiver-preauth",
                                "application/octet-stream",
                                &[b'x'; 65],
                                ""
                            )
                        )
                        .await,
                        413
                    ));
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            wire(
                                "/v1/receiver-preauth",
                                "application/octet-stream",
                                token.as_bytes(),
                                "Trailer: x-extra\r\n"
                            )
                        )
                        .await,
                        415
                    ));
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth?x=1", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    for path in ["/v1/causal-events", "/v1/causal-evidence/receiver"] {
                        assert!(code(
                            &send(
                                addr,
                                client.clone(),
                                wire(path, "application/json", b"{}", "")
                            )
                            .await,
                            403
                        ));
                    }
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        200
                    ));
                    assert!(
                        ticket
                            .receive()
                            .await
                            .unwrap()
                            .consume(&broker, owner, cid, deadline)
                            .is_ok()
                    );
                    let ticket = register();
                    let token = ticket.challenge();
                    let mut tasks = JoinSet::new();
                    for _ in 0..2 {
                        let c = client.clone();
                        let w = request("/v1/receiver-preauth", token.as_bytes());
                        tasks.spawn(async move { send(addr, c, w).await });
                    }
                    let first = tasks.join_next().await.unwrap().unwrap();
                    let second = tasks.join_next().await.unwrap().unwrap();
                    assert!(
                        (code(&first, 200) && code(&second, 403))
                            || (code(&first, 403) && code(&second, 200))
                    );
                    assert!(
                        ticket
                            .receive()
                            .await
                            .unwrap()
                            .consume(&broker, owner, cid, deadline)
                            .is_ok()
                    );
                    for mode in 0..3 {
                        let ticket = register();
                        let token = ticket.challenge();
                        assert!(code(
                            &send(
                                addr,
                                client.clone(),
                                request("/v1/receiver-preauth", token.as_bytes())
                            )
                            .await,
                            200
                        ));
                        let proof = ticket.receive().await.unwrap();
                        let other = ReceiverPreauth504::new();
                        other.activate().unwrap();
                        assert!(
                            match mode {
                                0 => proof.consume(&broker, [9; 32], cid, deadline),
                                1 => proof.consume(&broker, owner, [9; 32], deadline),
                                _ => proof.consume(&other, owner, cid, deadline),
                            }
                            .is_err()
                        );
                    }
                    let ticket = register();
                    let token = ticket.challenge();
                    drop(ticket);
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    let expired = broker
                        .register(
                            owner,
                            cid,
                            export_pin,
                            Instant::now() + Duration::from_millis(100),
                        )
                        .unwrap();
                    let token = expired.challenge();
                    tokio::time::sleep(Duration::from_millis(125)).await;
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    assert!(expired.receive().await.is_err());
                    let ticket = register();
                    let token = ticket.challenge();
                    let pending = ticket.receive();
                    drop(pending);
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        403
                    ));
                    let issued = register();
                    let token = issued.challenge();
                    assert!(code(
                        &send(
                            addr,
                            client.clone(),
                            request("/v1/receiver-preauth", token.as_bytes())
                        )
                        .await,
                        200
                    ));
                    let proof = issued.receive().await.unwrap();
                    let ticket = register();
                    let _ = stop.send(());
                    task.await.unwrap().unwrap();
                    assert!(ticket.receive().await.is_err());
                    assert!(proof.consume(&broker, owner, cid, deadline).is_err());
                },
            )
            .await
            .expect("overall preauth qualification deadline");
        });
}
