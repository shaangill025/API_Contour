#![cfg(unix)]

use contour_ingress::{BoundLaunchError, BoundLauncher, InertStarted, LaunchConfig};
use contour_postgres::{CausalIssuer, CausalMarkerBinder};

// This integration test is compiled as a downstream crate, so private-module
// visibility cannot accidentally mask an unusable public launch API.
#[allow(dead_code)]
async fn bind_from_downstream<'a>(
    started: InertStarted<'a>,
    issuer: &mut CausalIssuer,
    binder: &mut CausalMarkerBinder,
) -> Result<BoundLauncher<'a>, BoundLaunchError> {
    let config = LaunchConfig {
        product_credential: "product".into(),
        export_credential: "export".into(),
        batch_bytes: 4096,
        batch_events: 16,
        queue_bytes: 8192,
        queue_ttl_ms: 1000,
    };
    started.bind(issuer, binder, config).await
}
