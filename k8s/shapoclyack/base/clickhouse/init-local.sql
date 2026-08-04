-- Local compose mirror of k8s ConfigMap init.sql (ClickHouse first boot).
CREATE DATABASE IF NOT EXISTS shapoclyack;

CREATE TABLE IF NOT EXISTS shapoclyack.shapoclyack_vulnerabilities (
    tenant_id UUID,
    asset_ip IPv4,
    cve_id String,
    base_cvss Float32,
    epss_score Float32,
    asset_criticality UInt8,
    exploit_active UInt8,
    cisa_decision Enum8('Track' = 1, 'Attend' = 2, 'Act' = 3, 'Immediate' = 4),
    contextual_score Float32,
    scoring_model_version String,
    timestamp DateTime
) ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, asset_ip, cve_id);

CREATE TABLE IF NOT EXISTS shapoclyack.shapoclyack_open_ports (
    tenant_id UUID,
    target_ip IPv4,
    port UInt16,
    protocol LowCardinality(String),
    run_id String,
    timestamp DateTime
) ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, target_ip, port);
