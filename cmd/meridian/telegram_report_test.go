package main

import (
	"strings"
	"testing"
	"time"
)

func TestTelegramReportTokenRoundTrip(t *testing.T) {
	ciphertext, err := encryptTelegramBotToken("123456:example-token")
	if err != nil {
		t.Fatalf("encrypt token: %v", err)
	}
	plaintext, err := decryptTelegramBotToken(ciphertext)
	if err != nil {
		t.Fatalf("decrypt token: %v", err)
	}
	if plaintext != "123456:example-token" {
		t.Fatalf("round trip token = %q", plaintext)
	}

	public := telegramReportPublicSettings(telegramReportStoredSettings{
		TelegramReportSettings: TelegramReportSettings{ChatID: "-100123"},
		BotTokenCiphertext:     ciphertext,
	})
	if !public.BotTokenConfigured || public.BotToken != "" {
		t.Fatalf("public settings exposed token or lost configured state: configured=%v token=%q", public.BotTokenConfigured, public.BotToken)
	}
}

func TestTelegramReportDueUsesConfiguredSchedule(t *testing.T) {
	settings := telegramReportSettingsView{Enabled: true, Configured: true, ScheduleTime: "20:00", Frequency: "daily", Timezone: 480}
	now := time.Date(2026, time.August, 8, 20, 1, 0, 0, time.FixedZone("HKT", 8*60*60))
	key, due := telegramReportDue(now, settings)
	if !due || key != "daily:2026-08-08" {
		t.Fatalf("due = (%q, %v)", key, due)
	}
	before := now.Add(-2 * time.Hour)
	if _, due := telegramReportDue(before, settings); due {
		t.Fatal("report should not be due before configured time")
	}
}

func TestTelegramReportMessageIsBoundedAtUTF8Boundary(t *testing.T) {
	message := truncateTelegramText(strings.Repeat("客户端", 2000), telegramReportMaxMessageBytes)
	if len(message) > telegramReportMaxMessageBytes {
		t.Fatalf("message length = %d", len(message))
	}
	if !strings.HasSuffix(message, "...") {
		t.Fatal("long report should end with an ellipsis")
	}
}

func TestTelegramReportScheduleChangeRearmsCurrentPeriod(t *testing.T) {
	app := newTestApp(t)
	settings := TelegramReportSettings{
		Enabled: true, ChatID: "123456", ScheduleTime: "20:00", Frequency: "daily", Weekday: 1,
	}
	ciphertext, err := encryptTelegramBotToken("123456:example-token")
	if err != nil {
		t.Fatalf("encrypt token: %v", err)
	}
	if err := app.db.saveTelegramReportSettings(settings, ciphertext, true); err != nil {
		t.Fatalf("save initial settings: %v", err)
	}
	if err := app.db.markTelegramReportSent("daily:2026-08-10"); err != nil {
		t.Fatalf("mark sent: %v", err)
	}

	if err := app.db.saveTelegramReportSettings(settings, ciphertext, false); err != nil {
		t.Fatalf("save unchanged settings: %v", err)
	}
	stored, err := app.db.telegramReportSettings()
	if err != nil {
		t.Fatalf("read unchanged settings: %v", err)
	}
	if stored.LastSentKey != "daily:2026-08-10" {
		t.Fatalf("unchanged settings cleared last_sent_key: %q", stored.LastSentKey)
	}

	settings.ScheduleTime = "20:05"
	if err := app.db.saveTelegramReportSettings(settings, ciphertext, false); err != nil {
		t.Fatalf("save changed schedule: %v", err)
	}
	stored, err = app.db.telegramReportSettings()
	if err != nil {
		t.Fatalf("read changed settings: %v", err)
	}
	if stored.LastSentKey != "" {
		t.Fatalf("changed schedule kept last_sent_key: %q", stored.LastSentKey)
	}
}

func TestTelegramReportTrafficUsesGlobalBillingMode(t *testing.T) {
	app := newTestApp(t)
	site, err := app.db.CreateSite("telegram-billing", freePort(t), "http://127.0.0.1:8096", "", "direct", "[]", "infuse", 0, 0)
	if err != nil {
		t.Fatalf("CreateSite: %v", err)
	}
	now := time.Now()
	if err := app.db.addTrafficWithRequestsAt(site.ID, 10, 90, 1, now); err != nil {
		t.Fatalf("add traffic: %v", err)
	}

	dual, err := app.db.buildTelegramReportStats(now)
	if err != nil {
		t.Fatalf("build bidirectional stats: %v", err)
	}
	if dual.TodayTraffic != 100 || dual.HistoryTraffic != 100 || len(dual.TopTraffic) != 1 || dual.TopTraffic[0].Traffic != 100 {
		t.Fatalf("bidirectional stats = %+v, want traffic 100", dual)
	}

	settings := app.db.currentSystemSettings()
	settings.TrafficBillingMode = trafficBillingModeOutbound
	if err := app.db.saveSystemSettings(settings); err != nil {
		t.Fatalf("save outbound mode: %v", err)
	}
	outbound, err := app.db.buildTelegramReportStats(now)
	if err != nil {
		t.Fatalf("build outbound stats: %v", err)
	}
	if outbound.TodayTraffic != 90 || outbound.HistoryTraffic != 90 || len(outbound.TopTraffic) != 1 || outbound.TopTraffic[0].Traffic != 90 {
		t.Fatalf("outbound stats = %+v, want traffic 90", outbound)
	}
}
