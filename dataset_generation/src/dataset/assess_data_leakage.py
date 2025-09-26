"""Assess UKMDDoSDN v1.0 combined datasets for potential data leakage indicators."""

from __future__ import annotations

import argparse
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np
import pandas as pd

LOGGER = logging.getLogger("assess_data_leakage")

LEAKAGE_PATTERNS: Dict[str, Dict[str, Iterable[str]]] = {
    "target_leakage": {
        "description": "Features directly derived from target variable",
        "patterns": ["label", "class", "attack", "malicious", "benign", "normal"],
        "risk": "CRITICAL",
    },
    "statistical_leakage": {
        "description": "Pre-computed statistics that may include future knowledge",
        "patterns": ["avg_", "mean_", "std_", "var_", "min_", "max_", "sum_", "count_", "rate"],
        "risk": "HIGH",
    },
    "protocol_specific": {
        "description": "Protocol-specific identifiers that reveal signatures",
        "patterns": ["tcp_flags", "icmp_type", "tcp_seq", "tcp_ack", "urgent", "rst", "syn", "fin"],
        "risk": "MEDIUM",
    },
    "size_duration": {
        "description": "Size/duration metrics strongly tied to attack patterns",
        "patterns": ["duration", "length", "size", "bytes", "packet_count", "byte_count"],
        "risk": "LOW",
    },
    "infrastructure": {
        "description": "Network infrastructure identifiers that rarely help modelling",
        "patterns": [
            "switch_id",
            "port",
            "mac",
            "eth_",
            "vlan",
            "table_id",
            "cookie",
            "timestamp",
            "time",
            "seq",
            "sequence",
            "order",
            "index",
            "id",
        ],
        "risk": "LOW",
    },
}


@dataclass
class LeakageReport:
    dataset_name: str
    total_features: int
    leakage_detected: Dict[str, Dict[str, object]]
    uniqueness_summary: Dict[str, object]

    def to_dict(self) -> Dict[str, object]:
        return {
            "dataset": self.dataset_name,
            "total_features": self.total_features,
            "leakage": self.leakage_detected,
            "uniqueness": self.uniqueness_summary,
        }


def setup_logging(log_path: Path | None = None) -> None:
    handlers: List[logging.Handler] = [logging.StreamHandler()]
    if log_path:
        handlers.append(logging.FileHandler(log_path, mode="w", encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )


def detect_leakage(features: Iterable[str], dataset_name: str) -> Dict[str, Dict[str, object]]:
    leakage_summary: Dict[str, Dict[str, object]] = {}
    features = list(features)

    for category, info in LEAKAGE_PATTERNS.items():
        matches = []
        for feature in features:
            lower_feature = feature.lower()
            if any(pattern in lower_feature for pattern in info["patterns"]):
                matches.append(feature)
        if matches:
            leakage_summary[category] = {
                "description": info["description"],
                "risk": info["risk"],
                "matches": matches,
                "match_percentage": round(len(matches) / max(len(features), 1) * 100, 2),
            }
            LOGGER.warning(
                "[LEAKAGE] %s -> %s matches (%s%%)",
                dataset_name,
                category,
                leakage_summary[category]["match_percentage"],
            )
    return leakage_summary


def analyze_uniqueness(df: pd.DataFrame) -> Dict[str, object]:
    summary: Dict[str, object] = {
        "high_cardinality": [],
        "low_cardinality": [],
        "constant_features": [],
        "near_constant_features": [],
    }

    for column in df.columns:
        uniques = df[column].nunique(dropna=False)
        if uniques <= 1:
            summary["constant_features"].append(column)
        elif uniques < 5:
            summary["low_cardinality"].append(column)
        elif uniques > len(df) * 0.9:
            summary["high_cardinality"].append(column)
        elif uniques < len(df) * 0.05:
            summary["near_constant_features"].append(column)

    return summary


def load_dataset(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(csv_path)
    LOGGER.info("Loading dataset: %s", csv_path)
    return pd.read_csv(csv_path)


def assess_dataset(csv_path: Path, dataset_name: str) -> LeakageReport:
    df = load_dataset(csv_path)
    leakage = detect_leakage(df.columns, dataset_name)
    uniqueness = analyze_uniqueness(df)
    return LeakageReport(dataset_name, len(df.columns), leakage, uniqueness)


def summarize_reports(reports: Iterable[LeakageReport], output_path: Path | None) -> None:
    for report in reports:
        LOGGER.info("\n=== %s ===", report.dataset_name)
        LOGGER.info("Total features: %s", report.total_features)
        if report.leakage_detected:
            for category, data in report.leakage_detected.items():
                LOGGER.info("  - %s (%s): %s", category, data["risk"], len(data["matches"]))
        else:
            LOGGER.info("  No leakage patterns detected")
        for key, items in report.uniqueness_summary.items():
            LOGGER.debug("  %s: %s", key, items[:5] if isinstance(items, list) else items)

    if output_path:
        payload = [report.to_dict() for report in reports]
        output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        LOGGER.info("Saved JSON summary to %s", output_path)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Assess datasets for potential data leakage")
    parser.add_argument("--path", default="../main_output/v3", help="Directory containing CSV datasets")
    parser.add_argument(
        "--datasets",
        nargs="*",
        default=["flow_dataset.csv", "packet_dataset.csv", "cicflow_dataset.csv"],
        help="Dataset files to assess",
    )
    parser.add_argument("--log", type=Path, default=None, help="Optional log file path")
    parser.add_argument("--json", type=Path, default=None, help="Optional JSON report path")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    dataset_dir = Path(args.path).resolve()
    if not dataset_dir.exists():
        print(f"[FAIL] Dataset directory not found: {dataset_dir}")
        return 1

    setup_logging(args.log)
    LOGGER.info("Assessing datasets in %s", dataset_dir)

    reports: List[LeakageReport] = []
    for dataset in args.datasets:
        csv_path = dataset_dir / dataset
        try:
            report = assess_dataset(csv_path, dataset)
            reports.append(report)
        except FileNotFoundError:
            LOGGER.warning("Dataset file missing: %s", csv_path)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("Failed to process %s: %s", csv_path, exc)

    if not reports:
        LOGGER.error("No datasets processed")
        return 1

    summarize_reports(reports, args.json)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
