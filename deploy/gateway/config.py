"""Generate the local-only Envoy transport fixture configuration."""

IMAGE = "envoyproxy/envoy:v1.37.11@sha256:7765ad61185fca9c9a770c9e2cad640d085d708ae9c22f3741345e88331472a4"


def config(upstream_ip, upstream_port, upstream_name="upstream.test", ca="/fixture/ca.pem", *, listen_address="0.0.0.0", listen_port=8443):
    if listen_address not in ("0.0.0.0", "127.0.0.1"):
        raise ValueError("unsupported fixture listener address")
    if type(listen_port) is not int or not 1024 <= listen_port <= 65535:
        raise ValueError("fixture listener port must be unprivileged")
    tls = "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3."
    return {"static_resources": {
        "listeners": [{"name": "https", "address": {"socket_address": {"address": listen_address, "port_value": listen_port}},
            "per_connection_buffer_limit_bytes": 65536,
            "filter_chains": [{"transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {
                "@type": tls + "DownstreamTlsContext", "common_tls_context": {"tls_certificates": [{"certificate_chain": {"filename": "/fixture/down.pem"}, "private_key": {"filename": "/fixture/down.key"}}]}}},
                "filters": [{"name": "envoy.filters.network.http_connection_manager", "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                    "stat_prefix": "gateway", "codec_type": "HTTP1", "stream_idle_timeout": "10s",
                    "request_headers_timeout": "5s", "common_http_protocol_options": {"idle_timeout": "10s", "max_headers_count": 100},
                    "route_config": {"name": "fixed", "virtual_hosts": [{"name": "fixed", "domains": ["gateway.test"], "routes": [{"match": {"prefix": "/"}, "route": {"cluster": "upstream", "timeout": "15s"}}]}]},
                    "http_filters": [{"name": "envoy.filters.http.router", "typed_config": {"@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"}}]}}]}]}],
        "clusters": [{"name": "upstream", "type": "STRICT_DNS", "connect_timeout": "3s", "per_connection_buffer_limit_bytes": 65536,
            "circuit_breakers": {"thresholds": [{"max_connections": 32, "max_pending_requests": 32, "max_requests": 32, "max_retries": 0}]},
            "load_assignment": {"cluster_name": "upstream", "endpoints": [{"lb_endpoints": [{"endpoint": {"address": {"socket_address": {"address": upstream_ip, "port_value": upstream_port}}}}]}]},
            "transport_socket": {"name": "envoy.transport_sockets.tls", "typed_config": {"@type": tls + "UpstreamTlsContext", "sni": upstream_name,
                "common_tls_context": {"tls_params": {"tls_minimum_protocol_version": "TLSv1_2", "tls_maximum_protocol_version": "TLSv1_3"}, "validation_context": {"trusted_ca": {"filename": ca}, "match_typed_subject_alt_names": [{"san_type": "DNS", "matcher": {"exact": upstream_name}}]}}}}}]}}
