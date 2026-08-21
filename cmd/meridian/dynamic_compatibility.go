package main

import (
	"fmt"
)

func dynamicDefaultPolicy() DynamicDefaultPolicy {
	sources, _ := dynamicDiscoverySourcesForProfile(dynamicProfileCompatible)
	return DynamicDefaultPolicy{
		DynamicDiscoveryEnabled:    true,
		DynamicProfile:             dynamicProfileCompatible,
		DynamicDiscoverySources:    sources,
		DynamicDomainRules:         []DynamicDomainRule{},
		DynamicAllowHTTPSDowngrade: true,
	}
}

// DynamicRollbackReadiness reports existing enabled sites whose current policy
// cannot be represented by the canonical profile defaults. It is diagnostic
// only and never mutates site configuration.
func (d *DB) DynamicRollbackReadiness() (DynamicRollbackReadiness, error) {
	rows, err := d.db.Query("SELECT dynamic_profile, dynamic_discovery_sources, dynamic_domain_rules FROM sites WHERE dynamic_discovery_enabled=1")
	if err != nil {
		return DynamicRollbackReadiness{}, err
	}
	defer rows.Close()

	var readiness DynamicRollbackReadiness
	for rows.Next() {
		var profile, storedSources, storedRules string
		if err := rows.Scan(&profile, &storedSources, &storedRules); err != nil {
			return DynamicRollbackReadiness{}, err
		}
		sources, err := decodeDynamicDiscoverySources(storedSources)
		if err != nil || sources == nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery sources")
		}
		sources, err = normalizeDynamicDiscoverySourcesForAPI(profile, sources)
		if err != nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery sources: %w", err)
		}
		canonicalSources, ok := dynamicDiscoverySourcesForProfile(profile)
		if !ok {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic discovery profile")
		}
		if !dynamicDiscoverySourcesEqual(sources, canonicalSources) {
			readiness.EnabledLegacySourceSubsets++
		}

		rules, err := decodeDynamicDomainRules(storedRules)
		if err != nil || rules == nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic domain rules")
		}
		rules, err = normalizeDynamicDomainRules(profile, rules)
		if err != nil {
			return DynamicRollbackReadiness{}, fmt.Errorf("invalid stored dynamic domain rules: %w", err)
		}
		if profile == dynamicProfileSafe && len(rules) == 0 {
			readiness.EnabledSafeEmptyRules++
		}
	}
	if err := rows.Err(); err != nil {
		return DynamicRollbackReadiness{}, err
	}
	return readiness, nil
}
