package prismid_test

import (
	"testing"

	"github.com/yrZhaoweb/prismid/server/go/internal/bench"
)

func TestAccuracyConfusionMatrixBenchmark(t *testing.T) {
	cohorts, fpr, fnr, err := bench.RunFullConfusionMatrixBenchmark()
	if err != nil {
		t.Fatalf("RunFullConfusionMatrixBenchmark failed: %v", err)
	}
	for _, c := range cohorts {
		t.Logf("[%s] %-68s | %d/%d | %s", c.Category, c.CohortName, c.CorrectCount, c.TotalCases, c.RateLabel)
		if c.ErrorCount != 0 {
			t.Errorf("cohort %q had %d errors (expected 0)", c.CohortName, c.ErrorCount)
		}
	}
	t.Logf("SYNTHETIC RULE REGRESSION (1,000 cases): Rule FPR = %.2f%%, Rule FNR = %.2f%%", fpr, fnr)
	if fpr != 0 || fnr != 0 {
		t.Fatalf("expected 0.00%% rule FPR and 0.00%% rule FNR, got FPR=%.2f%% FNR=%.2f%%", fpr, fnr)
	}
}
