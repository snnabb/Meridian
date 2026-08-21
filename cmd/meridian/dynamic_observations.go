package main

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	dynamicObservationSourceRedirect     = dynamicDiscoverySourceRedirect
	dynamicObservationSourcePlaybackInfo = dynamicDiscoverySourcePlaybackInfo
	dynamicObservationSourceHLS          = dynamicDiscoverySourceHLS
	dynamicObservationSourceDASH         = dynamicDiscoverySourceDASH

	dynamicObservationTargetSameAuthority = "same_authority"
	dynamicObservationTargetConfigured    = "configured"
	dynamicObservationTargetDiscovered    = "discovered"

	dynamicObservationStageResponse   = "response"
	dynamicObservationStageLocation   = "location"
	dynamicObservationStagePolicy     = "policy"
	dynamicObservationStageResolve    = "resolve"
	dynamicObservationStageConnect    = "connect"
	dynamicObservationStageCapacity   = "capacity"
	dynamicObservationStageParse      = "parse"
	dynamicObservationStageCapability = "capability"
	dynamicObservationStageRuntime    = "runtime"

	dynamicObservationDecisionAllowed = "allowed"
	dynamicObservationDecisionDenied  = "denied"

	dynamicObservationReasonRedirectAllowed      = "redirect_allowed"
	dynamicObservationReasonInvalidLocation      = "invalid_location"
	dynamicObservationReasonUnsupportedStatus    = "unsupported_status"
	dynamicObservationReasonRedirectLoop         = "redirect_loop"
	dynamicObservationReasonHopLimit             = "hop_limit"
	dynamicObservationReasonSchemeDenied         = "scheme_denied"
	dynamicObservationReasonPortDenied           = "port_denied"
	dynamicObservationReasonDomainDenied         = "domain_denied"
	dynamicObservationReasonHTTPSDowngradeDenied = "https_downgrade_denied"
	dynamicObservationReasonSelfTarget           = "self_target"
	dynamicObservationReasonDNSFailure           = "dns_failure"
	dynamicObservationReasonAddressDenied        = "address_denied"
	dynamicObservationReasonDialFailure          = "dial_failure"
	dynamicObservationReasonTLSFailure           = "tls_failure"
	dynamicObservationReasonCapacityLimit        = "capacity_limit"
	dynamicObservationReasonRateLimit            = "rate_limit"
	dynamicObservationReasonResponseFailure      = "response_failure"
	dynamicObservationReasonRuntimeUnavailable   = "runtime_unavailable"

	dynamicObservationQueueCapacity                  = 2048
	dynamicObservationBatchSize                      = 128
	dynamicObservationRetentionDays                  = 30
	dynamicObservationPerSiteRowLimit                = 500
	dynamicObservationGlobalRowLimit                 = 10000
	dynamicObservationRetention                      = dynamicObservationRetentionDays * 24 * time.Hour
	dynamicObservationMaintenanceInterval            = time.Hour
	dynamicObservationReasonCandidateAllowed         = "candidate_allowed"
	dynamicObservationReasonParseFailure             = "parse_failure"
	dynamicObservationReasonCapabilityInvalid        = "capability_invalid"
	dynamicObservationReasonCapabilityExpired        = "capability_expired"
	dynamicObservationReasonRequestUnclassified      = "request_unclassified"
	dynamicObservationReasonStructuredBodyLimit      = "structured_body_limit"
	dynamicObservationReasonPlaybackInfoDenied       = "playback_info_denied"
	dynamicObservationReasonHLSFeatureDenied         = "hls_feature_denied"
	dynamicObservationReasonDASHFeatureDenied        = "dash_feature_denied"
	dynamicObservationReasonRedirectBodyReplayDenied = "redirect_body_replay_denied"
	dynamicObservationMaxAuthorityBytes              = 512
)

// dynamicObservationEvent is the complete hot-path observation contract. The
// database owns timestamps and aggregation so callers cannot inject chronology
// or counts into the operator-facing record.
type dynamicObservationEvent struct {
	SiteID             int64
	CanonicalAuthority string
	Source             string
	TargetKind         string
	Decision           string
	ReasonCode         string
	RedirectStatus     int
}

// DynamicObservation is deliberately identical to the frozen database/API
// shape. It never carries a redirect path, query, address, header, or body.
type DynamicObservation struct {
	SiteID             int64  `json:"site_id"`
	CanonicalAuthority string `json:"canonical_authority"`
	Source             string `json:"source"`
	TargetKind         string `json:"target_kind"`
	Stage              string `json:"stage"`
	Decision           string `json:"decision"`
	ReasonCode         string `json:"reason_code"`
	RedirectStatus     int    `json:"redirect_status"`
	FirstSeenMS        int64  `json:"first_seen_ms"`
	LastSeenMS         int64  `json:"last_seen_ms"`
	Count              int64  `json:"count"`
}

type DynamicObservationsResponse struct {
	Observations              []DynamicObservation `json:"observations"`
	DroppedObservations       uint64               `json:"dropped_observations,omitempty"`
	DroppedObservationsGlobal uint64               `json:"dropped_observations_global"`
	RetentionDays             int                  `json:"retention_days"`
	PerSiteRowLimit           int                  `json:"per_site_row_limit"`
	GlobalRowLimit            int                  `json:"global_row_limit"`
}

func dynamicObservationStageForReason(reasonCode string) (string, bool) {
	switch reasonCode {
	case dynamicObservationReasonRedirectAllowed,
		dynamicObservationReasonUnsupportedStatus,
		dynamicObservationReasonResponseFailure:
		return dynamicObservationStageResponse, true
	case dynamicObservationReasonInvalidLocation,
		dynamicObservationReasonRedirectLoop,
		dynamicObservationReasonHopLimit:
		return dynamicObservationStageLocation, true
	case dynamicObservationReasonCandidateAllowed,
		dynamicObservationReasonSchemeDenied,
		dynamicObservationReasonPortDenied,
		dynamicObservationReasonDomainDenied,
		dynamicObservationReasonHTTPSDowngradeDenied,
		dynamicObservationReasonSelfTarget,
		dynamicObservationReasonPlaybackInfoDenied,
		dynamicObservationReasonHLSFeatureDenied,
		dynamicObservationReasonDASHFeatureDenied:
		return dynamicObservationStagePolicy, true
	case dynamicObservationReasonDNSFailure,
		dynamicObservationReasonAddressDenied:
		return dynamicObservationStageResolve, true
	case dynamicObservationReasonDialFailure,
		dynamicObservationReasonTLSFailure:
		return dynamicObservationStageConnect, true
	case dynamicObservationReasonCapacityLimit,
		dynamicObservationReasonRateLimit:
		return dynamicObservationStageCapacity, true
	case dynamicObservationReasonParseFailure,
		dynamicObservationReasonRequestUnclassified,
		dynamicObservationReasonStructuredBodyLimit,
		dynamicObservationReasonRedirectBodyReplayDenied:
		return dynamicObservationStageParse, true
	case dynamicObservationReasonCapabilityInvalid,
		dynamicObservationReasonCapabilityExpired:
		return dynamicObservationStageCapability, true
	case dynamicObservationReasonRuntimeUnavailable:
		return dynamicObservationStageRuntime, true
	default:
		return "", false
	}
}

func validDynamicObservationTargetKind(targetKind string) bool {
	switch targetKind {
	case dynamicObservationTargetSameAuthority,
		dynamicObservationTargetConfigured,
		dynamicObservationTargetDiscovered:
		return true
	default:
		return false
	}
}

func validDynamicObservationRedirectStatus(status int) bool {
	return status == 0 || status >= 300 && status <= 399
}

func validDynamicObservationRouteDimensions(source, targetKind string, redirectStatus int) bool {
	if !validDynamicObservationTargetKind(targetKind) || !validDynamicObservationRedirectStatus(redirectStatus) {
		return false
	}
	return source == dynamicObservationSourceRedirect || redirectStatus == 0
}

func validDynamicObservationEnums(source, decision, reasonCode string) bool {
	switch source {
	case dynamicObservationSourceRedirect,
		dynamicObservationSourcePlaybackInfo,
		dynamicObservationSourceHLS,
		dynamicObservationSourceDASH:
	default:
		return false
	}
	switch decision {
	case dynamicObservationDecisionAllowed:
		return reasonCode == dynamicObservationReasonRedirectAllowed || reasonCode == dynamicObservationReasonCandidateAllowed
	case dynamicObservationDecisionDenied:
		switch reasonCode {
		case dynamicObservationReasonInvalidLocation,
			dynamicObservationReasonUnsupportedStatus,
			dynamicObservationReasonRedirectLoop,
			dynamicObservationReasonHopLimit,
			dynamicObservationReasonSchemeDenied,
			dynamicObservationReasonPortDenied,
			dynamicObservationReasonDomainDenied,
			dynamicObservationReasonHTTPSDowngradeDenied,
			dynamicObservationReasonSelfTarget,
			dynamicObservationReasonDNSFailure,
			dynamicObservationReasonAddressDenied,
			dynamicObservationReasonDialFailure,
			dynamicObservationReasonTLSFailure,
			dynamicObservationReasonCapacityLimit,
			dynamicObservationReasonRateLimit,
			dynamicObservationReasonParseFailure,
			dynamicObservationReasonRequestUnclassified,
			dynamicObservationReasonStructuredBodyLimit,
			dynamicObservationReasonPlaybackInfoDenied,
			dynamicObservationReasonHLSFeatureDenied,
			dynamicObservationReasonDASHFeatureDenied,
			dynamicObservationReasonRedirectBodyReplayDenied,
			dynamicObservationReasonCapabilityInvalid,
			dynamicObservationReasonCapabilityExpired,
			dynamicObservationReasonResponseFailure,
			dynamicObservationReasonRuntimeUnavailable:
			return true
		}
	}
	return false
}

func isCanonicalDynamicObservationAuthority(value string) bool {
	if value == "" || len(value) > dynamicObservationMaxAuthorityBytes || strings.TrimSpace(value) != value {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.User != nil || parsed.Host == "" || parsed.Opaque != "" {
		return false
	}
	if parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" {
		return false
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	if err != nil || host == "" || portText == "" {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
		return false
	}
	normalizedHost, _, err := normalizeDynamicHost(host)
	if err != nil {
		return false
	}
	return value == parsed.Scheme+"://"+net.JoinHostPort(normalizedHost, portText)
}

func (d *DB) EnqueueDynamicObservation(event dynamicObservationEvent) {
	stage, stageOK := dynamicObservationStageForReason(event.ReasonCode)
	if event.SiteID <= 0 || !validDynamicObservationEnums(event.Source, event.Decision, event.ReasonCode) || !stageOK || !validDynamicObservationRouteDimensions(event.Source, event.TargetKind, event.RedirectStatus) || !isCanonicalDynamicObservationAuthority(event.CanonicalAuthority) {
		d.droppedDynamicObservations.Add(1)
		return
	}
	command := dynamicObservationCommand{
		kind: dynamicObservationCommandWrite,
		event: queuedDynamicObservation{
			event:        event,
			stage:        stage,
			observedAtMS: time.Now().UnixMilli(),
		},
	}
	if !d.dynamicObservationGate.TryRLock() {
		d.droppedDynamicObservations.Add(1)
		return
	}
	defer d.dynamicObservationGate.RUnlock()
	if d.dynamicObservationClosed.Load() || d.dynamicObservationQueue == nil {
		d.droppedDynamicObservations.Add(1)
		return
	}
	select {
	case d.dynamicObservationQueue <- command:
	default:
		d.droppedDynamicObservations.Add(1)
	}
}

func (d *DB) DroppedDynamicObservations() uint64 {
	if d == nil {
		return 0
	}
	return d.droppedDynamicObservations.Load()
}

func (d *DB) ClearDynamicObservations(siteID int64) error {
	if siteID <= 0 {
		return fmt.Errorf("invalid dynamic observation site id")
	}
	return d.sendDynamicObservationControl(dynamicObservationCommandClear, siteID)
}

func (d *DB) ListDynamicObservations(siteID int64) ([]DynamicObservation, error) {
	if siteID <= 0 {
		return nil, fmt.Errorf("invalid dynamic observation site id")
	}
	// The ordered barrier makes observations already accepted by the nonblocking
	// queue visible before the read begins.
	if err := d.flushDynamicObservations(); err != nil {
		return nil, err
	}
	rows, err := d.db.Query(`
		SELECT site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status, first_seen_ms, last_seen_ms, count
		FROM dynamic_observations
		WHERE site_id=?
		ORDER BY last_seen_ms DESC, first_seen_ms DESC, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status`, siteID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	observations := make([]DynamicObservation, 0)
	for rows.Next() {
		var observation DynamicObservation
		if err := rows.Scan(
			&observation.SiteID,
			&observation.CanonicalAuthority,
			&observation.Source,
			&observation.TargetKind,
			&observation.Stage,
			&observation.Decision,
			&observation.ReasonCode,
			&observation.RedirectStatus,
			&observation.FirstSeenMS,
			&observation.LastSeenMS,
			&observation.Count,
		); err != nil {
			return nil, err
		}
		expectedStage, stageOK := dynamicObservationStageForReason(observation.ReasonCode)
		if observation.SiteID != siteID || !isCanonicalDynamicObservationAuthority(observation.CanonicalAuthority) || !validDynamicObservationEnums(observation.Source, observation.Decision, observation.ReasonCode) || !validDynamicObservationRouteDimensions(observation.Source, observation.TargetKind, observation.RedirectStatus) || !stageOK || observation.Stage != expectedStage || observation.FirstSeenMS < 0 || observation.LastSeenMS < observation.FirstSeenMS || observation.Count <= 0 {
			return nil, fmt.Errorf("stored dynamic observation failed validation")
		}
		observations = append(observations, observation)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return observations, nil
}

func (d *DB) writeDynamicObservationBatch(batch []queuedDynamicObservation) (int, error) {
	type observationKey struct {
		siteID             int64
		canonicalAuthority string
		source             string
		targetKind         string
		stage              string
		decision           string
		reasonCode         string
		redirectStatus     int
	}
	type aggregate struct {
		event       dynamicObservationEvent
		stage       string
		firstSeenMS int64
		lastSeenMS  int64
		count       int64
	}
	aggregated := make([]aggregate, 0, len(batch))
	indexes := make(map[observationKey]int, len(batch))
	for _, queued := range batch {
		event := queued.event
		key := observationKey{
			siteID:             event.SiteID,
			canonicalAuthority: event.CanonicalAuthority,
			source:             event.Source,
			targetKind:         event.TargetKind,
			stage:              queued.stage,
			decision:           event.Decision,
			reasonCode:         event.ReasonCode,
			redirectStatus:     event.RedirectStatus,
		}
		if index, ok := indexes[key]; ok {
			current := &aggregated[index]
			current.firstSeenMS = min(current.firstSeenMS, queued.observedAtMS)
			current.lastSeenMS = max(current.lastSeenMS, queued.observedAtMS)
			current.count++
			continue
		}
		indexes[key] = len(aggregated)
		aggregated = append(aggregated, aggregate{
			event:       event,
			stage:       queued.stage,
			firstSeenMS: queued.observedAtMS,
			lastSeenMS:  queued.observedAtMS,
			count:       1,
		})
	}

	tx, err := d.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	statement, err := tx.Prepare(`
		INSERT INTO dynamic_observations
			(site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status, first_seen_ms, last_seen_ms, count)
		SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
		WHERE EXISTS (SELECT 1 FROM sites WHERE id=?)
		ON CONFLICT(site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status) DO UPDATE SET
			first_seen_ms=MIN(dynamic_observations.first_seen_ms, excluded.first_seen_ms),
			last_seen_ms=MAX(dynamic_observations.last_seen_ms, excluded.last_seen_ms),
			count=CASE
				WHEN excluded.count >= 9223372036854775807-dynamic_observations.count THEN 9223372036854775807
				ELSE dynamic_observations.count+excluded.count
			END`)
	if err != nil {
		return 0, err
	}
	defer statement.Close()
	skipped := 0
	for _, current := range aggregated {
		event := current.event
		result, err := statement.Exec(
			event.SiteID,
			event.CanonicalAuthority,
			event.Source,
			event.TargetKind,
			current.stage,
			event.Decision,
			event.ReasonCode,
			event.RedirectStatus,
			current.firstSeenMS,
			current.lastSeenMS,
			current.count,
			event.SiteID,
		)
		if err != nil {
			return 0, err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return 0, err
		}
		if rows == 0 {
			skipped += int(current.count)
		}
	}
	if err := pruneDynamicObservationRows(context.Background(), tx, time.Now()); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return skipped, nil
}

type dynamicObservationSQLExecutor interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}

func pruneDynamicObservationRows(ctx context.Context, executor dynamicObservationSQLExecutor, now time.Time) error {
	cutoffMS := now.Add(-dynamicObservationRetention).UnixMilli()
	if _, err := executor.ExecContext(ctx, "DELETE FROM dynamic_observations WHERE last_seen_ms<?", cutoffMS); err != nil {
		return err
	}
	if _, err := executor.ExecContext(ctx, `
		DELETE FROM dynamic_observations
		WHERE (site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status) IN (
			SELECT site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status
			FROM (
				SELECT site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status,
					ROW_NUMBER() OVER (
						PARTITION BY site_id
						ORDER BY last_seen_ms DESC, first_seen_ms DESC, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status
					) AS row_number
				FROM dynamic_observations
			)
			WHERE row_number > ?
		)`, dynamicObservationPerSiteRowLimit); err != nil {
		return err
	}
	_, err := executor.ExecContext(ctx, `
		DELETE FROM dynamic_observations
		WHERE (site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status) IN (
			SELECT site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status
			FROM dynamic_observations
			ORDER BY last_seen_ms DESC, first_seen_ms DESC, site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status
			LIMIT -1 OFFSET ?
		)`, dynamicObservationGlobalRowLimit)
	return err
}

func (d *DB) pruneDynamicObservations() error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := pruneDynamicObservationRows(context.Background(), tx, time.Now()); err != nil {
		return err
	}
	return tx.Commit()
}
