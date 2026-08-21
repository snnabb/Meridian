package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

const dynamicObservationStageSQLCase = `CASE
	WHEN reason_code IN ('redirect_allowed', 'unsupported_status', 'response_failure') THEN 'response'
	WHEN reason_code IN ('invalid_location', 'redirect_loop', 'hop_limit') THEN 'location'
	WHEN reason_code IN ('candidate_allowed', 'scheme_denied', 'port_denied', 'domain_denied', 'https_downgrade_denied', 'self_target', 'playback_info_denied', 'hls_feature_denied', 'dash_feature_denied') THEN 'policy'
	WHEN reason_code IN ('dns_failure', 'address_denied') THEN 'resolve'
	WHEN reason_code IN ('dial_failure', 'tls_failure') THEN 'connect'
	WHEN reason_code IN ('capacity_limit', 'rate_limit') THEN 'capacity'
	WHEN reason_code IN ('parse_failure', 'request_unclassified', 'structured_body_limit', 'redirect_body_replay_denied') THEN 'parse'
	WHEN reason_code IN ('capability_invalid', 'capability_expired') THEN 'capability'
	WHEN reason_code = 'runtime_unavailable' THEN 'runtime'
	ELSE NULL
END`

const dynamicObservationRouteTableDDLPrefix = `
CREATE TABLE dynamic_observations (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	canonical_authority TEXT NOT NULL,
	source TEXT NOT NULL CHECK(source IN ('redirect', 'playback_info', 'hls', 'dash')),
	target_kind TEXT NOT NULL CHECK(target_kind IN ('same_authority', 'configured', 'discovered')),
	stage TEXT NOT NULL CHECK(stage IN ('response', 'location', 'policy', 'resolve', 'connect', 'capacity', 'parse', 'capability', 'runtime'))
		CHECK(stage = ` + dynamicObservationStageSQLCase + `),
	decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
	reason_code TEXT NOT NULL CHECK(reason_code IN (
		'redirect_allowed',
		'candidate_allowed',
		'invalid_location',
		'unsupported_status',
		'redirect_loop',
		'hop_limit',
		'scheme_denied',
		'port_denied',
		'domain_denied',
		'https_downgrade_denied',
		'self_target',
		'dns_failure',
		'address_denied',
		'dial_failure',
		'tls_failure',
		'capacity_limit',
		'rate_limit',
		'parse_failure',
		'request_unclassified',
		'structured_body_limit',
		'playback_info_denied',
		'hls_feature_denied',
		'dash_feature_denied',
		'redirect_body_replay_denied',
		'capability_invalid',
		'capability_expired',
		'response_failure',
		'runtime_unavailable'
	)),
	redirect_status INTEGER NOT NULL CHECK(redirect_status = 0 OR redirect_status BETWEEN 300 AND 399),
	first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
	last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
	count INTEGER NOT NULL CHECK(count > 0),
	CHECK(
		(decision = 'allowed' AND reason_code IN ('redirect_allowed', 'candidate_allowed')) OR
		(decision = 'denied' AND reason_code NOT IN ('redirect_allowed', 'candidate_allowed'))
	),`

const dynamicObservationRouteTableDDLSuffix = `
	PRIMARY KEY(site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status)
) WITHOUT ROWID;`

const dynamicObservationTableDDL = dynamicObservationRouteTableDDLPrefix + `
	CHECK(source = 'redirect' OR redirect_status = 0),` + dynamicObservationRouteTableDDLSuffix

const dynamicObservationPreviousTableDDL = dynamicObservationRouteTableDDLPrefix + `
	CHECK(source = 'redirect' OR (target_kind = 'discovered' AND redirect_status = 0)),` + dynamicObservationRouteTableDDLSuffix

const dynamicObservationV19TableDDL = `
CREATE TABLE dynamic_observations (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	canonical_authority TEXT NOT NULL,
	source TEXT NOT NULL CHECK(source IN ('redirect', 'playback_info', 'hls', 'dash')),
	decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
	reason_code TEXT NOT NULL CHECK(reason_code IN (
		'redirect_allowed',
		'candidate_allowed',
		'invalid_location',
		'unsupported_status',
		'redirect_loop',
		'hop_limit',
		'scheme_denied',
		'port_denied',
		'domain_denied',
		'https_downgrade_denied',
		'self_target',
		'dns_failure',
		'address_denied',
		'dial_failure',
		'tls_failure',
		'capacity_limit',
		'rate_limit',
		'parse_failure',
		'request_unclassified',
		'structured_body_limit',
		'playback_info_denied',
		'hls_feature_denied',
		'dash_feature_denied',
		'redirect_body_replay_denied',
		'capability_invalid',
		'capability_expired',
		'response_failure',
		'runtime_unavailable'
	)),
	first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
	last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
	count INTEGER NOT NULL CHECK(count > 0),
	PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
) WITHOUT ROWID;`

const dynamicObservationV18TableDDL = `
CREATE TABLE dynamic_observations (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	canonical_authority TEXT NOT NULL,
	source TEXT NOT NULL CHECK(source IN ('redirect', 'playback_info', 'hls', 'dash')),
	decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
	reason_code TEXT NOT NULL CHECK(reason_code IN (
		'redirect_allowed', 'candidate_allowed', 'invalid_location', 'unsupported_status',
		'redirect_loop', 'hop_limit', 'scheme_denied', 'port_denied', 'domain_denied',
		'https_downgrade_denied', 'self_target', 'dns_failure', 'address_denied',
		'dial_failure', 'tls_failure', 'capacity_limit', 'rate_limit', 'parse_failure',
		'capability_invalid', 'capability_expired', 'response_failure', 'runtime_unavailable'
	)),
	first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
	last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
	count INTEGER NOT NULL CHECK(count > 0),
	PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
) WITHOUT ROWID;`

const dynamicObservationLegacyTableDDL = `
CREATE TABLE dynamic_observations (
	site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
	canonical_authority TEXT NOT NULL,
	source TEXT NOT NULL CHECK(source = 'redirect'),
	decision TEXT NOT NULL CHECK(decision IN ('allowed', 'denied')),
	reason_code TEXT NOT NULL CHECK(reason_code IN (
		'redirect_allowed', 'invalid_location', 'unsupported_status', 'redirect_loop',
		'hop_limit', 'scheme_denied', 'port_denied', 'domain_denied',
		'https_downgrade_denied', 'self_target', 'dns_failure', 'address_denied',
		'dial_failure', 'tls_failure', 'capacity_limit', 'rate_limit',
		'response_failure', 'runtime_unavailable'
	)),
	first_seen_ms INTEGER NOT NULL CHECK(first_seen_ms >= 0),
	last_seen_ms INTEGER NOT NULL CHECK(last_seen_ms >= first_seen_ms),
	count INTEGER NOT NULL CHECK(count > 0),
	PRIMARY KEY(site_id, canonical_authority, source, decision, reason_code)
) WITHOUT ROWID;`

const dynamicObservationIndexesDDL = `
CREATE INDEX IF NOT EXISTS idx_dynamic_observations_site_last_seen
	ON dynamic_observations(site_id, last_seen_ms DESC);
CREATE INDEX IF NOT EXISTS idx_dynamic_observations_last_seen
	ON dynamic_observations(last_seen_ms);`

const (
	dynamicObservationSchemaCurrent  = "current"
	dynamicObservationSchemaPrevious = "previous"
	dynamicObservationSchemaV19      = "v1.9"
	dynamicObservationSchemaV18      = "v1.8"
	dynamicObservationSchemaLegacy   = "legacy"
	dynamicObservationSchemaInvalid  = "invalid"
)

func compactSQLiteDDL(value string) string {
	var compact strings.Builder
	compact.Grow(len(value))
	for _, character := range strings.ToLower(value) {
		if !unicode.IsSpace(character) {
			compact.WriteRune(character)
		}
	}
	return strings.TrimSuffix(compact.String(), ";")
}

func dynamicObservationSchemaState(tableSQL string) string {
	compact := compactSQLiteDDL(tableSQL)
	switch compact {
	case compactSQLiteDDL(dynamicObservationTableDDL):
		return dynamicObservationSchemaCurrent
	case compactSQLiteDDL(dynamicObservationPreviousTableDDL):
		return dynamicObservationSchemaPrevious
	case compactSQLiteDDL(dynamicObservationV19TableDDL):
		return dynamicObservationSchemaV19
	case compactSQLiteDDL(dynamicObservationV18TableDDL):
		return dynamicObservationSchemaV18
	case compactSQLiteDDL(dynamicObservationLegacyTableDDL):
		return dynamicObservationSchemaLegacy
	default:
		return dynamicObservationSchemaInvalid
	}
}

type dynamicObservationColumnSpec struct {
	name               string
	typeName           string
	primaryKeyPosition int
}

func dynamicObservationExpectedColumns(state string) []dynamicObservationColumnSpec {
	if state == dynamicObservationSchemaCurrent || state == dynamicObservationSchemaPrevious {
		return []dynamicObservationColumnSpec{
			{name: "site_id", typeName: "INTEGER", primaryKeyPosition: 1},
			{name: "canonical_authority", typeName: "TEXT", primaryKeyPosition: 2},
			{name: "source", typeName: "TEXT", primaryKeyPosition: 3},
			{name: "target_kind", typeName: "TEXT", primaryKeyPosition: 4},
			{name: "stage", typeName: "TEXT", primaryKeyPosition: 5},
			{name: "decision", typeName: "TEXT", primaryKeyPosition: 6},
			{name: "reason_code", typeName: "TEXT", primaryKeyPosition: 7},
			{name: "redirect_status", typeName: "INTEGER", primaryKeyPosition: 8},
			{name: "first_seen_ms", typeName: "INTEGER"},
			{name: "last_seen_ms", typeName: "INTEGER"},
			{name: "count", typeName: "INTEGER"},
		}
	}
	return []dynamicObservationColumnSpec{
		{name: "site_id", typeName: "INTEGER", primaryKeyPosition: 1},
		{name: "canonical_authority", typeName: "TEXT", primaryKeyPosition: 2},
		{name: "source", typeName: "TEXT", primaryKeyPosition: 3},
		{name: "decision", typeName: "TEXT", primaryKeyPosition: 4},
		{name: "reason_code", typeName: "TEXT", primaryKeyPosition: 5},
		{name: "first_seen_ms", typeName: "INTEGER"},
		{name: "last_seen_ms", typeName: "INTEGER"},
		{name: "count", typeName: "INTEGER"},
	}
}

func validateDynamicObservationColumns(ctx context.Context, conn *sql.Conn, state string) error {
	expected := dynamicObservationExpectedColumns(state)
	rows, err := conn.QueryContext(ctx, `
		SELECT name, upper(type), "notnull", dflt_value, pk
		FROM pragma_table_info('dynamic_observations')
		ORDER BY cid`)
	if err != nil {
		return fmt.Errorf("inspect dynamic_observations schema: %w", err)
	}
	position := 0
	for rows.Next() {
		if position >= len(expected) {
			_ = rows.Close()
			return fmt.Errorf("dynamic_observations contains unexpected columns")
		}
		var name, typeName string
		var notNull, primaryKeyPosition int
		var defaultValue sql.NullString
		if err := rows.Scan(&name, &typeName, &notNull, &defaultValue, &primaryKeyPosition); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inspect dynamic_observations column: %w", err)
		}
		want := expected[position]
		if name != want.name || typeName != want.typeName || notNull != 1 || defaultValue.Valid || primaryKeyPosition != want.primaryKeyPosition {
			_ = rows.Close()
			return fmt.Errorf("dynamic_observations column %d has an invalid definition", position)
		}
		position++
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect dynamic_observations schema: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close dynamic_observations schema rows: %w", err)
	}
	if position != len(expected) {
		return fmt.Errorf("dynamic_observations is missing required columns")
	}
	return nil
}

func validateDynamicObservationIndexes(ctx context.Context, conn *sql.Conn) error {
	type indexSpec struct {
		name    string
		columns []string
		desc    []int
	}
	expected := []indexSpec{
		{name: "idx_dynamic_observations_site_last_seen", columns: []string{"site_id", "last_seen_ms"}, desc: []int{0, 1}},
		{name: "idx_dynamic_observations_last_seen", columns: []string{"last_seen_ms"}, desc: []int{0}},
	}
	expectedNames := make(map[string]bool, len(expected))
	for _, index := range expected {
		expectedNames[index.name] = true
	}
	rows, err := conn.QueryContext(ctx, `SELECT name, "unique", origin, partial FROM pragma_index_list('dynamic_observations') ORDER BY name`)
	if err != nil {
		return fmt.Errorf("inspect dynamic observation indexes: %w", err)
	}
	seen := make(map[string]bool, len(expected))
	primaryIndexes := 0
	for rows.Next() {
		var name, origin string
		var unique, partial int
		if err := rows.Scan(&name, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return fmt.Errorf("inspect dynamic observation index: %w", err)
		}
		if origin == "pk" {
			if unique != 1 || partial != 0 {
				_ = rows.Close()
				return fmt.Errorf("dynamic observation primary index has an invalid definition")
			}
			primaryIndexes++
			continue
		}
		if origin != "c" || unique != 0 || partial != 0 || !expectedNames[name] || seen[name] {
			_ = rows.Close()
			return fmt.Errorf("dynamic observations contains an unexpected index %q", name)
		}
		seen[name] = true
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("inspect dynamic observation indexes: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close dynamic observation index rows: %w", err)
	}
	if primaryIndexes != 1 || len(seen) != len(expected) {
		return fmt.Errorf("dynamic observation indexes are incomplete")
	}
	for _, index := range expected {
		indexRows, err := conn.QueryContext(ctx, `SELECT name, "desc" FROM pragma_index_xinfo(?) WHERE "key"=1 ORDER BY seqno`, index.name)
		if err != nil {
			return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
		}
		position := 0
		for indexRows.Next() {
			if position >= len(index.columns) {
				_ = indexRows.Close()
				return fmt.Errorf("dynamic observation index %s has an invalid definition", index.name)
			}
			var column sql.NullString
			var descending int
			if err := indexRows.Scan(&column, &descending); err != nil {
				_ = indexRows.Close()
				return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
			}
			if !column.Valid || column.String != index.columns[position] || descending != index.desc[position] {
				_ = indexRows.Close()
				return fmt.Errorf("dynamic observation index %s has an invalid definition", index.name)
			}
			position++
		}
		if err := indexRows.Err(); err != nil {
			_ = indexRows.Close()
			return fmt.Errorf("inspect dynamic observation index %s: %w", index.name, err)
		}
		if err := indexRows.Close(); err != nil {
			return fmt.Errorf("close dynamic observation index %s rows: %w", index.name, err)
		}
		if position != len(index.columns) {
			return fmt.Errorf("dynamic observation index %s has an invalid definition", index.name)
		}
	}
	return nil
}

func validateDynamicObservationSchemaShape(ctx context.Context, conn *sql.Conn, state string) error {
	if err := validateDynamicObservationColumns(ctx, conn, state); err != nil {
		return err
	}
	return validateDynamicObservationIndexes(ctx, conn)
}

func ensureDynamicObservationSchema(ctx context.Context, conn *sql.Conn) error {
	var tableSQL string
	err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='dynamic_observations'").Scan(&tableSQL)
	if errors.Is(err, sql.ErrNoRows) {
		if _, err := conn.ExecContext(ctx, dynamicObservationTableDDL+dynamicObservationIndexesDDL); err != nil {
			return fmt.Errorf("create dynamic_observations schema: %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect dynamic_observations table SQL: %w", err)
	}
	state := dynamicObservationSchemaState(tableSQL)
	if state == dynamicObservationSchemaCurrent {
		return nil
	}
	var migrationProjection string
	switch state {
	case dynamicObservationSchemaPrevious:
		migrationProjection = "site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status, first_seen_ms, last_seen_ms, count"
	case dynamicObservationSchemaV19, dynamicObservationSchemaV18, dynamicObservationSchemaLegacy:
		// Schemas before route dimensions did not retain enough information to
		// reconstruct target classification or redirect status.
		migrationProjection = "site_id, canonical_authority, source, 'discovered', " + dynamicObservationStageSQLCase + ", decision, reason_code, 0, first_seen_ms, last_seen_ms, count"
	default:
		return fmt.Errorf("dynamic_observations contains unrecognized or unsafe constraints")
	}
	if err := validateDynamicObservationSchemaShape(ctx, conn, state); err != nil {
		return fmt.Errorf("validate previous dynamic_observations schema: %w", err)
	}
	var staleTable int
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='dynamic_observations_legacy'").Scan(&staleTable); err != nil {
		return fmt.Errorf("inspect legacy dynamic observation table: %w", err)
	}
	if staleTable != 0 {
		return fmt.Errorf("dynamic_observations_legacy already exists")
	}
	// #nosec G202 -- every fragment is a compile-time constant selected only after the legacy schema shape has been validated; no request or database value is interpolated.
	migrationSQL := `
ALTER TABLE dynamic_observations RENAME TO dynamic_observations_legacy;
` + dynamicObservationTableDDL + `
INSERT INTO dynamic_observations
	(site_id, canonical_authority, source, target_kind, stage, decision, reason_code, redirect_status, first_seen_ms, last_seen_ms, count)
SELECT ` + migrationProjection + `
FROM dynamic_observations_legacy;
DROP TABLE dynamic_observations_legacy;
` + dynamicObservationIndexesDDL
	if _, err := conn.ExecContext(ctx, migrationSQL); err != nil {
		return fmt.Errorf("migrate dynamic_observations route dimensions: %w", err)
	}
	return nil
}

func validateDynamicObservationSchema(ctx context.Context, conn *sql.Conn) error {
	var tableSQL string
	if err := conn.QueryRowContext(ctx, "SELECT sql FROM sqlite_master WHERE type='table' AND name='dynamic_observations'").Scan(&tableSQL); err != nil {
		return fmt.Errorf("inspect dynamic_observations table SQL: %w", err)
	}
	if dynamicObservationSchemaState(tableSQL) != dynamicObservationSchemaCurrent {
		return fmt.Errorf("dynamic_observations constraints are invalid")
	}
	return validateDynamicObservationSchemaShape(ctx, conn, dynamicObservationSchemaCurrent)
}
