use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
pub(super) struct Fixture(PathBuf);
impl Fixture {
    pub(super) fn new() -> Self {
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
        // This test-only fixture spawns a process. Avoid inheriting another
        // concurrently running test's live advisory-lock descriptor before exec.
        #[cfg(unix)]
        let _process_guard = crate::causal_owner::PROCESS_TEST_LOCK.lock().unwrap();
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
            extension.push_str("subjectAltName=DNS:upstream.test\n");
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
    pub(super) fn read(&self, name: &str) -> Vec<u8> {
        fs::read(self.0.join(name)).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("owned synthetic fixture cleanup");
    }
}
