package config

import (
	"testing"
	"time"
)

func TestRuntimeBudgetsValidateConfiguredDurations(t *testing.T) {
	keys := []string{"VEIL_DB_CONNECT_TIMEOUT", "VEIL_STARTUP_AUDIT_TIMEOUT", "VEIL_WS_AUTH_TIMEOUT", "VEIL_WS_READ_TIMEOUT", "VEIL_WS_MUTATION_TIMEOUT", "VEIL_WS_EPHEMERAL_TIMEOUT", "VEIL_SHUTDOWN_TIMEOUT", "VEIL_SHUTDOWN_GRACE"}
	for _, key := range keys {
		for _, value := range []string{"", "0s", "-1s", "invalid", "24h", " 1s"} {
			t.Run(key+"/"+value, func(t *testing.T) {
				t.Setenv(key, value)
				if err := loadRuntimeBudgets(&Config{}); err == nil {
					t.Fatal("invalid duration accepted")
				}
			})
		}
	}
}

func TestRuntimeBudgetsSeparateStartupAndShutdownGrace(t *testing.T) {
	t.Setenv("VEIL_DB_CONNECT_TIMEOUT", "2s")
	t.Setenv("VEIL_STARTUP_AUDIT_TIMEOUT", "2m")
	t.Setenv("VEIL_SHUTDOWN_TIMEOUT", "20s")
	t.Setenv("VEIL_SHUTDOWN_GRACE", "10s")
	cfg := &Config{}
	if err := loadRuntimeBudgets(cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.DatabaseConnectTimeout != 2*time.Second || cfg.StartupAuditTimeout != 2*time.Minute {
		t.Fatal("startup budgets were combined")
	}
	t.Setenv("VEIL_SHUTDOWN_GRACE", "20s")
	if err := loadRuntimeBudgets(&Config{}); err == nil {
		t.Fatal("no time reserved for cancellation and cleanup")
	}
}
