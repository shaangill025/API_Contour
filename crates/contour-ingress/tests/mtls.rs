//! Actual loopback TLS with independently generated synthetic X.509 credentials.
use contour_ingress::{CollectorTls, TlsError};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, ServerName},
};
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "contour-ingress-mtls-{}-{nonce}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let fixture = Self(path);
        // Do not inherit host request extensions from the OpenSSL configuration.
        fs::write(
            fixture.0.join("fixture.cnf"),
            "[req]\ndistinguished_name=dn\n[dn]\n",
        )
        .unwrap();
        fixture.ca("ca");
        fixture.ca("other");
        fixture.leaf("server", "ca", "serverAuth", true);
        fixture.leaf("client", "ca", "clientAuth", false);
        fixture.leaf("untrusted", "other", "clientAuth", false);
        fixture.leaf("wrong-purpose", "ca", "serverAuth", false);
        fixture
    }
    fn command(&self, args: &[&str]) {
        let mut child = Command::new("openssl")
            .args(args)
            .current_dir(&self.0)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("fixture OpenSSL available");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success(), "synthetic certificate command failed");
                return;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("synthetic certificate command deadline");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    fn ca(&self, name: &str) {
        self.command(&[
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
        self.command(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
    }
    fn leaf(&self, name: &str, ca: &str, purpose: &str, server: bool) {
        self.command(&[
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
        fs::write(self.0.join(format!("{name}.ext")), extension).unwrap();
        self.command(&[
            "x509",
            "-req",
            "-in",
            &format!("{name}.csr"),
            "-CA",
            &format!("{ca}.pem"),
            "-CAkey",
            &format!("{ca}.key"),
            "-set_serial",
            match name {
                "server" => "2",
                "client" => "3",
                "untrusted" => "4",
                _ => "5",
            },
            "-days",
            "1",
            "-extfile",
            &format!("{name}.ext"),
            "-out",
            &format!("{name}.pem"),
        ]);
        self.command(&[
            "x509",
            "-in",
            &format!("{name}.pem"),
            "-outform",
            "DER",
            "-out",
            &format!("{name}.der"),
        ]);
        self.command(&[
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
        fs::read(self.0.join(name)).unwrap()
    }
    fn server(&self, deadline: Duration) -> CollectorTls {
        // Diagnose synthetic fixture configuration without printing key material.
        let provider = rustls::crypto::ring::default_provider();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.read("ca.der")))
            .expect("synthetic root DER");
        rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(provider.clone()),
        )
        .build()
        .expect("synthetic client verifier");
        let key = PrivateKeyDer::try_from(self.read("server.key.der"))
            .expect("synthetic private-key DER encoding");
        rustls::sign::CertifiedKey::from_der(
            vec![CertificateDer::from(self.read("server.der"))],
            key,
            &provider,
        )
        .expect("synthetic server certificate and private-key consistency");
        CollectorTls::from_der(
            &[&self.read("server.der")],
            &self.read("server.key.der"),
            &[&self.read("ca.der")],
            deadline,
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
        fs::remove_dir_all(&self.0).expect("owned synthetic fixture cleanup");
    }
}

async fn handshake(
    tls: Arc<CollectorTls>,
    client: Arc<ClientConfig>,
    version: &'static rustls::SupportedProtocolVersion,
) -> Result<Vec<u8>, TlsError> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let mut server = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tls.accept(socket).await?;
        let connection = &stream.get_ref().1;
        assert_eq!(connection.alpn_protocol(), Some(b"http/1.1".as_slice()));
        assert_eq!(connection.protocol_version(), Some(version.version));
        assert_eq!(
            connection.handshake_kind(),
            Some(rustls::HandshakeKind::Full)
        );
        let certificate = connection
            .peer_certificates()
            .and_then(|chain| chain.first())
            .map(|cert| cert.to_vec())
            .unwrap_or_default();
        let mut byte = [0];
        timeout(Duration::from_secs(2), stream.read_exact(&mut byte))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(byte, [7]);
        stream.write_all(&[8]).await.unwrap();
        Ok(certificate)
    });
    let connector = TlsConnector::from(client);
    let socket = TcpStream::connect(address).await.unwrap();
    let client = timeout(Duration::from_secs(2), async {
        let mut stream = connector
            .connect(
                ServerName::try_from("localhost").unwrap().to_owned(),
                socket,
            )
            .await?;
        stream.write_all(&[7]).await?;
        let mut byte = [0];
        stream.read_exact(&mut byte).await?;
        assert_eq!(byte, [8]);
        Ok::<_, std::io::Error>(())
    })
    .await;
    let result = match timeout(Duration::from_secs(3), &mut server).await {
        Ok(joined) => joined.unwrap(),
        Err(_) => {
            server.abort();
            let _ = server.await;
            panic!("owned server handshake deadline");
        }
    };
    assert_eq!(
        client.is_ok_and(|result| result.is_ok()),
        result.is_ok(),
        "both peers confirm authentication"
    );
    result
}

#[test]
fn actual_mtls_requires_valid_client_certificate_and_supports_tls12_tls13() {
    let fixture = Fixture::new();
    let certificate = fixture.read("server.der");
    let key = fixture.read("server.key.der");
    let root = fixture.read("ca.der");
    let good = Duration::from_secs(2);
    for (chain, roots, key, deadline) in [
        (vec![], vec![root.as_slice()], key.as_slice(), good),
        (
            vec![certificate.as_slice(); 9],
            vec![root.as_slice()],
            key.as_slice(),
            good,
        ),
        (vec![certificate.as_slice()], vec![], key.as_slice(), good),
        (
            vec![certificate.as_slice()],
            vec![root.as_slice(); 9],
            key.as_slice(),
            good,
        ),
        (
            vec![certificate.as_slice()],
            vec![root.as_slice()],
            b"".as_slice(),
            good,
        ),
        (
            vec![certificate.as_slice()],
            vec![root.as_slice()],
            key.as_slice(),
            Duration::ZERO,
        ),
        (
            vec![certificate.as_slice()],
            vec![root.as_slice()],
            key.as_slice(),
            Duration::from_secs(31),
        ),
    ] {
        assert_eq!(
            CollectorTls::from_der(&chain, key, &roots, deadline).unwrap_err(),
            TlsError::Configuration
        );
    }
    let excess = vec![0; 65_537];
    assert_eq!(
        CollectorTls::from_der(&[&excess], &key, &[&root], good).unwrap_err(),
        TlsError::Configuration
    );
    assert_eq!(
        CollectorTls::from_der(&[&certificate], &key, &[&excess], good).unwrap_err(),
        TlsError::Configuration
    );
    assert_eq!(
        CollectorTls::from_der(&[&certificate], &vec![0; 16_385], &[&root], good).unwrap_err(),
        TlsError::Configuration
    );
    assert_eq!(
        CollectorTls::from_der(&[b"malformed"], &key, &[&root], good).unwrap_err(),
        TlsError::Configuration
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
                let tls = Arc::new(fixture.server(Duration::from_secs(2)));
                let client = fixture.client(Some("client"), version);
                // Reuse both configurations: subsequent connections still perform full mTLS.
                for _ in 0..2 {
                    assert_eq!(
                        handshake(tls.clone(), client.clone(), version)
                            .await
                            .unwrap(),
                        fixture.read("client.der")
                    );
                }
                for identity in [None, Some("untrusted"), Some("wrong-purpose")] {
                    assert_eq!(
                        handshake(tls.clone(), fixture.client(identity, version), version)
                            .await
                            .unwrap_err(),
                        TlsError::Handshake
                    );
                }
            }
        });
}

#[test]
fn stalled_handshake_times_out_and_cancelled_accept_closes_owned_socket() {
    let fixture = Fixture::new();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let tls = fixture.server(Duration::from_millis(20));
            assert_eq!(tls.accept(socket).await.unwrap_err(), TlsError::Deadline);
            assert_eq!(
                timeout(Duration::from_secs(1), peer.read(&mut [0]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
            let mut peer = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (socket, _) = listener.accept().await.unwrap();
            let tls = fixture.server(Duration::from_secs(2));
            let mut accepting = Box::pin(tls.accept(socket));
            std::future::poll_fn(|context| {
                assert!(matches!(
                    std::future::Future::poll(accepting.as_mut(), context),
                    std::task::Poll::Pending
                ));
                std::task::Poll::Ready(())
            })
            .await;
            drop(accepting);
            assert_eq!(
                timeout(Duration::from_secs(1), peer.read(&mut [0]))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        });
}
