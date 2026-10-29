use contour_core::{
    CapturePoint, CaptureProvenance, CausalClassificationClaim, CausalLink, CausalLinks,
    CollectorIdentity, DestinationService, DiscoveryError, MAX_CAUSAL_LINKS, TlsLeg,
    WorkloadIdentity,
};

const IDS: [&str; 8] = [
    "00000000-0000-0000-0000-000000000001",
    "00000000-0000-0000-0000-000000000002",
    "00000000-0000-0000-0000-000000000003",
    "00000000-0000-0000-0000-000000000004",
    "00000000-0000-0000-0000-000000000005",
    "00000000-0000-0000-0000-000000000006",
    "00000000-0000-0000-0000-000000000007",
    "00000000-0000-0000-0000-000000000008",
];

#[test]
fn instances_and_restart_lifecycles_remain_distinct_from_collector() {
    let first = WorkloadIdentity::new([IDS[0], IDS[1], IDS[2], IDS[3], IDS[4], IDS[5]]).unwrap();
    let concurrent =
        WorkloadIdentity::new([IDS[0], IDS[1], IDS[2], IDS[3], IDS[4], IDS[6]]).unwrap();
    let restarted =
        WorkloadIdentity::new([IDS[0], IDS[1], IDS[2], IDS[3], IDS[4], IDS[7]]).unwrap();
    let collector = CollectorIdentity::new(IDS[5]).unwrap();
    assert_ne!(first, concurrent);
    assert_ne!(first, restarted);
    assert_eq!(first.deployment(), concurrent.deployment());
    assert_eq!(collector.id(), first.instance()); // Equal syntax does not equate identity roles.
    assert_eq!(first.tenant(), IDS[0]);
    assert_eq!(first.project(), IDS[1]);
    assert_eq!(first.service(), IDS[2]);
    assert_eq!(first.environment(), IDS[3]);
}

#[test]
fn bounds_and_closed_provenance_do_not_accept_trace_context_as_identity() {
    assert!(CollectorIdentity::new("traceparent: secret").is_err());
    assert!(DestinationService::new("example.com").is_err());
    assert!(WorkloadIdentity::new([IDS[0], IDS[1], IDS[2], IDS[3], IDS[4], "42"]).is_err());
    let destination = DestinationService::new(IDS[6]).unwrap();
    assert_eq!(destination.id(), IDS[6]); // Approval is external to this syntax check.
    let provenance = CaptureProvenance {
        point: CapturePoint::Gateway,
        tls_leg: TlsLeg::GatewayToUpstream,
    };
    assert_eq!(provenance.tls_leg, TlsLeg::GatewayToUpstream);
    let verified =
        CausalLink::new(IDS[5], IDS[6], CausalClassificationClaim::VerifiedClaimed).unwrap();
    let inferred =
        CausalLink::new(IDS[5], IDS[6], CausalClassificationClaim::InferredClaimed).unwrap();
    let missing =
        CausalLink::new(IDS[5], IDS[6], CausalClassificationClaim::MissingClaimed).unwrap();
    let links = CausalLinks::new(vec![verified.clone(), inferred, missing]).unwrap();
    assert_eq!(
        links
            .links()
            .iter()
            .map(CausalLink::claim)
            .collect::<Vec<_>>(),
        vec![
            CausalClassificationClaim::VerifiedClaimed,
            CausalClassificationClaim::InferredClaimed,
            CausalClassificationClaim::MissingClaimed
        ]
    );
    assert_eq!(
        CausalLinks::new(vec![verified; MAX_CAUSAL_LINKS + 1]),
        Err(DiscoveryError::TooManyLinks)
    );
    assert!(!format!("{links:?} {destination:?}").contains(IDS[6]));
}

#[test]
fn identifiers_use_existing_canonical_uuid_syntax() {
    assert!(CollectorIdentity::new("ABCDEF00-0000-0000-0000-000000000000").is_err());
    assert!(CollectorIdentity::new("abcdef00-0000-0000-0000-00000000000").is_err());
    assert!(CollectorIdentity::new("abcdef00-0000-0000-0000-0000000000000").is_err());
    assert!(CollectorIdentity::new("abcdef00-0000-0000-0000-000000000000").is_ok());
}

#[test]
fn links_are_bounded_claims_not_a_validated_graph() {
    let self_link =
        CausalLink::new(IDS[5], IDS[5], CausalClassificationClaim::VerifiedClaimed).unwrap();
    let links = CausalLinks::new(vec![self_link.clone(), self_link]).unwrap();
    assert_eq!(links.links().len(), 2);
    assert_eq!(
        links.links()[0].claim(),
        CausalClassificationClaim::VerifiedClaimed
    );
    // No method on this representation promotes the claim to proof.
}
