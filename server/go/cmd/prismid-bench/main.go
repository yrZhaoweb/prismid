package main

import (
	"fmt"
	"os"

	"github.com/yrZhaoweb/prismid/server/go/internal/bench"
)

func main() {
	cohorts, fpr, fnr, err := bench.RunFullConfusionMatrixBenchmark()
	if err != nil {
		fmt.Fprintf(os.Stderr, "benchmark error: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("# PrismID v1.1.0 规则回归混淆矩阵基准报告 (1,000 合成向量压测)")
	fmt.Println()
	fmt.Println("> 说明：以下 1,000 组样本为受控合成规则回归测试集（用于验证高并发同款硬件防误连、同网段办公本/CGNAT 防误杀、浏览器升级与单用户清 Cookie 纵向稳定、以及多维攻击向量的图关联规则），不等同于公网全量真实流量的线上统计漏报率。")
	fmt.Println()
	fmt.Println("| 评估维度 | 压测场景 (Cohort) | 样本数 | 准确判定数 | 误判/漏判数 | 核心指标结果 |")
	fmt.Println("|---|---|---:|---:|---:|---|")
	for _, c := range cohorts {
		fmt.Printf("| **%s** | %s | %d | %d | %d | **`%s`** |\n",
			c.Category, c.CohortName, c.TotalCases, c.CorrectCount, c.ErrorCount, c.RateLabel)
	}
	fmt.Println()
	fmt.Printf("- **合成回归防误杀率 (Rule-Regression FPR — 500 正常高碰撞样本)**：**`%.2f%%`**\n", fpr)
	fmt.Printf("- **合成回归防漏报率 (Rule-Regression FNR — 500 对抗规则向量)**：**`%.2f%%`**（规则召回率 **`%.2f%%`**）\n", fnr, 100.0-fnr)
}
