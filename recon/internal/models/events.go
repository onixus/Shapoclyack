// Package models defines the JSON payloads exchanged over NATS JetStream
// between the recon task producer and shapoclyack-recon workers.
package models

// Seed identifies the starting point for a recon task (a domain, IP, CIDR, etc.).
type Seed struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// ReconTask is the JSON payload consumed from subject "recon.tasks.>".
type ReconTask struct {
	TaskID   string                 `json:"task_id"`
	TenantID string                 `json:"tenant_id"`
	Seed     Seed                   `json:"seed"`
	Config   map[string]interface{} `json:"config,omitempty"`
}

// Asset is one discovered artifact (subdomain, IP, etc.) within a ReconResult.
type Asset struct {
	AssetType       string                 `json:"asset_type"`
	Value           string                 `json:"value"`
	DiscoveryMethod string                 `json:"discovery_method"`
	IsAlive         bool                   `json:"is_alive"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ReconResult is the JSON payload published to subject "recon.results.{tenant_id}".
type ReconResult struct {
	TaskID           string  `json:"task_id"`
	TenantID         string  `json:"tenant_id"`
	Status           string  `json:"status"`
	DiscoveredAssets []Asset `json:"discovered_assets"`
}
