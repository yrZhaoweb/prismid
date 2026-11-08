package prismid

import (
	"testing"
)

func TestAccuracyConfusionMatrixBenchmark(t *testing.T) {
	cohorts, fpr, fnr, err := RunFullConfusionMatrixBenchmark()
	if err != nil {
		t.Fatalf("RunFullConfusionMatrixBenchmark failed: %v", err)
	}
	for _, c := range cohorts {
		t.Logf("[%s] %-68s | %d/%d | %s", c.Category, c.CohortName, c.CorrectCount, c.TotalCases, c.RateLabel)
		if c.ErrorCount != 0 {
			t.Errorf("cohort %q had %d errors (expected 0)", c.CohortName, c.ErrorCount)
		}
	}
	t.Logf("OVERALL BENCHMARK (1,000 cases): False Positive Rate (FPR) = %.2f%%, False Negative Rate (FNR) = %.2f%%", fpr, fnr)
	if fpr != 0 || fnr != 0 {
		t.Fatalf("expected 0.00%% FPR and 0.00%% FNR, got FPR=%.2f%% FNR=%.2f%%", fpr, fnr)
	}
}
