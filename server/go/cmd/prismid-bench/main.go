package main

import (
	"fmt"
	"os"

	prismid "github.com/yrZhaoweb/prismid/server/go"
)

func main() {
	cohorts, fpr, fnr, err := prismid.RunFullConfusionMatrixBenchmark()
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("# PrismID v0.2.0 混淆矩阵准确率基准评测报告 (1,000 样本压测)")
	fmt.Println()
	fmt.Println("| 评估维度 | 压测场景 (Cohort) | 样本数 | 准确判定数 | 误判/漏判数 | 核心指标结果 |")
	fmt.Println("|---|---|---:|---:|---:|---|")
	for _, c := range cohorts {
		fmt.Printf("| **%s** | %s | %d | %d | %d | **`%s`** |\n",
			c.Category, c.CohortName, c.TotalCases, c.CorrectCount, c.ErrorCount, c.RateLabel)
	}
	fmt.Println()
	fmt.Printf("- **综合误杀率 (False Positive Rate, FPR — 500 正常高碰撞样本)**：**`%.2f%%`**\n", fpr)
	fmt.Printf("- **综合漏报率 (False Negative Rate, FNR — 500 黑产对抗样本)**：**`%.2f%%`**（召回率 **`%.2f%%`**）\n", fnr, 100.0-fnr)
}
