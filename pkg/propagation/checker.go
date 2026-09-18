package propagation

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/m5rcel-vibecodes/dnsfuck/pkg/records"
	"github.com/m5rcel-vibecodes/dnsfuck/pkg/resolver"
)

// Item holds the response of a single resolver in a propagation check.
type Item struct {
	ResolverName  string           `json:"resolver_name"`
	ResolverHost  string           `json:"resolver_host"`
	Location      string           `json:"location,omitempty"`
	RcodeName     string           `json:"rcode_name"`
	Latency       time.Duration    `json:"latency_ns"`
	LatencyStr    string           `json:"latency"`
	Records       []records.Record `json:"records"`
	AnswerSummary string           `json:"answer_summary"`
	MinTTL        uint32           `json:"min_ttl,omitempty"`
	MaxTTL        uint32           `json:"max_ttl,omitempty"`
	Signature     string           `json:"signature"`
	Error         string           `json:"error,omitempty"`
}

// Result holds the consolidated propagation results across all resolvers.
type Result struct {
	Domain               string        `json:"domain"`
	Type                 string        `json:"type"`
	Items                []Item        `json:"items"`
	DisagreementDetected bool          `json:"disagreement_detected"`
	UniqueAnswerSets     int           `json:"unique_answer_sets"`
	TotalResolvers       int           `json:"total_resolvers"`
	ResponsiveResolvers  int           `json:"responsive_resolvers"`
	TotalDuration        time.Duration `json:"total_duration_ns"`
}

// Check queries multiple resolvers concurrently and determines whether answers agree worldwide.
func Check(ctx context.Context, domain string, qtype uint16, timeout time.Duration, customResolvers []resolver.Resolver) *Result {
	start := time.Now()
	cleanDomain := records.NormalizeDomain(domain)
	typeName := records.Uint16ToType(qtype)

	var targets []struct {
		res      resolver.Resolver
		location string
	}

	if len(customResolvers) > 0 {
		for _, r := range customResolvers {
			targets = append(targets, struct {
				res      resolver.Resolver
				location string
			}{res: r, location: "Custom"})
		}
	} else {
		for _, pub := range GlobalResolvers {
			targets = append(targets, struct {
				res      resolver.Resolver
				location string
			}{res: pub.ToResolver(timeout), location: pub.Location})
		}
	}

	result := &Result{
		Domain:         cleanDomain,
		Type:           typeName,
		TotalResolvers: len(targets),
		Items:          make([]Item, len(targets)),
	}

	var wg sync.WaitGroup
	wg.Add(len(targets))

	for i, t := range targets {
		go func(idx int, r resolver.Resolver, loc string) {
			defer wg.Done()
			qRes := r.Query(ctx, domain, qtype)

			item := Item{
				ResolverName: r.Name,
				ResolverHost: r.Host,
				Location:     loc,
				RcodeName:    qRes.RcodeName,
				Latency:      qRes.Latency,
				LatencyStr:   qRes.LatencyFormatted,
				Records:      qRes.Records,
				Error:        qRes.Error,
			}

			if len(qRes.Records) > 0 {
				var vals []string
				minTTL := qRes.Records[0].TTL
				maxTTL := qRes.Records[0].TTL

				for _, rec := range qRes.Records {
					vals = append(vals, rec.Value)
					if rec.TTL < minTTL {
						minTTL = rec.TTL
					}
					if rec.TTL > maxTTL {
						maxTTL = rec.TTL
					}
				}

				// Canonical sorted list for deterministic comparison
				sort.Strings(vals)
				item.AnswerSummary = strings.Join(vals, ", ")
				item.MinTTL = minTTL
				item.MaxTTL = maxTTL
				item.Signature = item.AnswerSummary
			} else if item.Error != "" {
				item.Signature = "[ERROR] " + item.Error
				item.AnswerSummary = item.Error
			} else {
				item.Signature = fmt.Sprintf("[%s]", item.RcodeName)
				item.AnswerSummary = fmt.Sprintf("(%s - No records)", item.RcodeName)
			}

			result.Items[idx] = item
		}(i, t.res, t.location)
	}

	wg.Wait()

	// Analyze agreement
	answerSetCount := make(map[string]int)
	responsive := 0

	for _, item := range result.Items {
		if item.Error == "" {
			responsive++
			answerSetCount[item.Signature]++
		}
	}

	result.ResponsiveResolvers = responsive
	result.UniqueAnswerSets = len(answerSetCount)

	// If we got responsive resolvers with more than 1 distinct answer set, there is disagreement
	if len(answerSetCount) > 1 {
		result.DisagreementDetected = true
	}

	result.TotalDuration = time.Since(start)
	return result
}
