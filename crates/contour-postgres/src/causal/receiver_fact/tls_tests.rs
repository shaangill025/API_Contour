//! Opt-in, synthetic loopback TLS evidence; no external services or credentials.
use super::*;
use rustls::{ClientConfig, pki_types::ServerName};
use std::{
    fs::{self, DirBuilder},
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Instant as WallInstant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::timeout,
};
use tokio_rustls::TlsConnector;

const LIMIT: Duration = Duration::from_secs(4);

struct Fixture {
    dir: PathBuf,
    openssl: PathBuf,
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
        let fixture = Self { dir, openssl };
        fs::write(
            fixture.dir.join("fixture.cnf"),
            "[req]\ndistinguished_name=dn\n[dn]\n",
        )
        .unwrap();
        fixture.ca("ca");
        fixture.ca("other");
        fixture.leaf("server", "ca", "serverAuth", true, "2");
        fixture.leaf("client", "ca", "clientAuth", false, "3");
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
        let deadline = WallInstant::now() + Duration::from_secs(15);
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
            "rsa:2048",
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
            "rsa:2048",
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

async fn exchange(
    server: Arc<ReceiverEvidenceTls>,
    client: Arc<ClientConfig>,
    version: &'static rustls::SupportedProtocolVersion,
    expected_digest: [u8; 32],
) -> Result<(), ReceiverTlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = server.accept_until(socket, Instant::now() + LIMIT).await?;
        assert_eq!(
            stream.stream.get_ref().1.protocol_version(),
            Some(version.version)
        );
        assert_eq!(
            stream.stream.get_ref().1.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(stream.peer().leaf, expected_digest);
        let mut byte = [0];
        timeout(LIMIT, stream.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(byte, [7]);
        assert_eq!(stream.peer().leaf, expected_digest);
        timeout(LIMIT, stream.write_all(&[8]))
            .await
            .unwrap()
            .unwrap();
        Ok(())
    });
    let client_result = timeout(LIMIT, async {
        let socket = TcpStream::connect(address).await?;
        let mut stream = TlsConnector::from(client)
            .connect(
                ServerName::try_from("localhost").unwrap().to_owned(),
                socket,
            )
            .await?;
        stream.write_all(&[7]).await?;
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        assert_eq!(byte, [8]);
        Ok::<_, io::Error>(())
    })
    .await;
    let result = match timeout(LIMIT, &mut task).await {
        Ok(result) => result.unwrap(),
        Err(_) => {
            task.abort();
            let _ = task.await;
            panic!("owned loopback server deadline");
        }
    };
    if result.is_ok() {
        assert!(client_result.is_ok_and(|x| x.is_ok()));
    }
    result
}

#[test]
#[ignore = "requires explicit qualified OpenSSL binary"]
fn qualified_loopback_receiver_mtls() {
    let fixture = Fixture::new();
    let expected: [u8; 32] = fixture.read("client.sha256").try_into().unwrap();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                let server = Arc::new(fixture.server());
                let client = fixture.client(Some("client"), version);
                // Reused client configuration exercises its session cache, while the
                // server must perform full client authentication on every connection.
                for _ in 0..2 {
                    assert!(
                        exchange(server.clone(), client.clone(), version, expected)
                            .await
                            .is_ok()
                    );
                }
                for identity in [None, Some("untrusted"), Some("wrong-purpose")] {
                    assert_eq!(
                        exchange(
                            server.clone(),
                            fixture.client(identity, version),
                            version,
                            expected
                        )
                        .await,
                        Err(ReceiverTlsError::Handshake)
                    );
                }
            }
            let server = fixture.server();
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            for expired in [false, true] {
                let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (socket, _) = listener.accept().await.unwrap();
                let deadline = if expired {
                    Instant::now()
                } else {
                    Instant::now() + Duration::from_millis(30)
                };
                let result = timeout(LIMIT, server.accept_until(socket, deadline))
                    .await
                    .expect("bounded accept");
                assert!(matches!(result, Err(ReceiverTlsError::Deadline)));
                assert_eq!(
                    timeout(LIMIT, peer.read(&mut [0])).await.unwrap().unwrap(),
                    0
                );
            }
        });
}
