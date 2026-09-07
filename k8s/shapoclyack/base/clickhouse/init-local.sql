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
ORDER BY (tenant_id, asset_ip, cve_id)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS shapoclyack.shapoclyack_open_ports (
    tenant_id UUID,
    target_ip IPv4,
    port UInt16,
    protocol LowCardinality(String),
    run_id String,
    timestamp DateTime
) ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, target_ip, port)
TTL timestamp + INTERVAL 90 DAY;

CREATE TABLE IF NOT EXISTS shapoclyack.shapoclyack_controls (
    tenant_id UUID,
    run_id String,
    control LowCardinality(String),
    title String,
    status LowCardinality(String),
    impact LowCardinality(String),
    risk_level LowCardinality(String),
    coverage_checked UInt32,
    coverage_total UInt32,
    findings_critical UInt32,
    findings_high UInt32,
    findings_medium UInt32,
    findings_low UInt32,
    overall_verdict LowCardinality(String),
    overall_risk LowCardinality(String),
    timestamp DateTime
) ENGINE = ReplacingMergeTree()
ORDER BY (tenant_id, control, timestamp, run_id)
TTL timestamp + INTERVAL 365 DAY;
