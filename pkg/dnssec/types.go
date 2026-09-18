package dnssec

import (
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
)

// Status represents the high-level DNSSEC state of a domain.
type Status string

const (
	StatusSecure        Status = "SECURE"        // Fully signed with valid DS & DNSKEY
	StatusUnsigned      Status = "UNSIGNED"      // Normal domain with no DNSSEC configured
	StatusBogus         Status = "BOGUS"         // Broken chain, missing key, or signature mismatch
	StatusIndeterminate Status = "INDETERMINATE" // Cannot confirm validation (e.g. resolver does not validate)
)

// KeyInfo describes a parsed DNSKEY record.
type KeyInfo struct {
	KeyTag    uint16 `json:"key_tag"`
	Algorithm string `json:"algorithm"`
	AlgoID    uint8  `json:"algorithm_id"`
	Type      string `json:"type"` // "KSK" or "ZSK"
	Flags     uint16 `json:"flags"`
	Bits      int    `json:"bits,omitempty"`
	PublicKey string `json:"public_key"`
}

// DSInfo describes a parsed DS record and its match against DNSKEY.
type DSInfo struct {
	KeyTag     uint16 `json:"key_tag"`
	Algorithm  string `json:"algorithm"`
	DigestType string `json:"digest_type"`
	Digest     string `json:"digest"`
	MatchesKey bool   `json:"matches_key"`
}

// RRSIGInfo describes an RRSIG record.
type RRSIGInfo struct {
	TypeCovered string    `json:"type_covered"`
	Algorithm   string    `json:"algorithm"`
	KeyTag      uint16    `json:"key_tag"`
	SignerName  string    `json:"signer_name"`
	Expiration  time.Time `json:"expiration"`
	Inception   time.Time `json:"inception"`
	IsExpired   bool      `json:"is_expired"`
}

// DiagnosticResult contains the full DNSSEC analysis.
type DiagnosticResult struct {
	Domain             string           `json:"domain"`
	Status             Status           `json:"status"`
	Summary            string           `json:"summary"`
	HasDNSKEY          bool             `json:"has_dnskey"`
	HasDS              bool             `json:"has_ds"`
	HasRRSIG           bool             `json:"has_rrsig"`
	ResolverAD         bool             `json:"resolver_ad"`           // Resolver returned AD flag
	ValidatingResolverAD bool           `json:"validating_resolver_ad"` // Validating public resolver returned AD flag
	ValidationNote     string           `json:"validation_note"`
	Keys               []KeyInfo        `json:"keys,omitempty"`
	DSRecords          []DSInfo         `json:"ds_records,omitempty"`
	Signatures         []RRSIGInfo      `json:"signatures,omitempty"`
	RawRecords         []records.Record `json:"raw_records,omitempty"`
	Errors             []string         `json:"errors,omitempty"`
	Duration           time.Duration    `json:"duration_ns"`
}
