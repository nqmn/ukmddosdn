"""Inspect UKMDDoSDN v1.0 combined CSV datasets for quality metrics and inconsistencies."""

from __future__ import annotations

import argparse
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List

import numpy as np
import pandas as pd

LOGGER = logging.getLogger("investigate_csv_quality")


@dataclass
class QualityReport:
    dataset_name: str
    total_rows: int
    total_columns: int
    missing_values: int
    infinite_values: int
    dtype_summary: Dict[str, str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "dataset": self.dataset_name,
            "rows": self.total_rows,
            "columns": self.total_columns,
            "missing_values": self.missing_values,
            "infinite_values": self.infinite_values,
            "dtypes": self.dtype_summary,
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


def load_dataset(csv_path: Path) -> pd.DataFrame:
    if not csv_path.exists():
        raise FileNotFoundError(csv_path)
    LOGGER.info("Loading %s", csv_path)
    return pd.read_csv(csv_path)


def compute_quality_metrics(df: pd.DataFrame) -> Dict[str, object]:
    missing = int(df.isna().sum().sum())
    infinite = int(np.isinf(df.select_dtypes(include=[float, int]).values).sum())
    dtype_summary = {column: str(dtype) for column, dtype in df.dtypes.items()}
    return {
        "missing_values": missing,
        "infinite_values": infinite,
        "dtype_summary": dtype_summary,
    }


def detect_inconsistencies(dfs: Dict[str, pd.DataFrame]) -> Dict[str, object]:
    inconsistencies: Dict[str, object] = {}
    if not dfs:
        return inconsistencies

    reference_columns = set(next(iter(dfs.values())).columns)
    for name, df in dfs.items():
        diff_missing = reference_columns - set(df.columns)
        diff_extra = set(df.columns) - reference_columns
        if diff_missing or diff_extra:
            inconsistencies[name] = {
                "missing_columns": sorted(diff_missing),
                "extra_columns": sorted(diff_extra),
            }
    return inconsistencies


def analyze_dataset(csv_path: Path, dataset_name: str) -> QualityReport:
    df = load_dataset(csv_path)
    metrics = compute_quality_metrics(df)
    return QualityReport(
        dataset_name,
        len(df),
        len(df.columns),
        metrics["missing_values"],
        metrics["infinite_values"],
        metrics["dtype_summary"],
    )


def summarize_reports(reports: Iterable[QualityReport], inconsistencies: Dict[str, object], output_json: Path | None) -> None:
    for report in reports:
        LOGGER.info("\n=== %s ===", report.dataset_name)
        LOGGER.info("Rows: %s | Columns: %s", report.total_rows, report.total_columns)
        LOGGER.info("Missing values: %s | Infinite values: %s", report.missing_values, report.infinite_values)
    if inconsistencies:
        LOGGER.warning("Column mismatches detected: %s", inconsistencies)

    if output_json:
        payload = {
            "reports": [report.to_dict() for report in reports],
            "inconsistencies": inconsistencies,
        }
        output_json.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        LOGGER.info("Saved JSON quality report to %s", output_json)


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Investigate CSV dataset quality")
    parser.add_argument("--path", default="../main_output/v2_main", help="Directory containing CSV datasets")
    parser.add_argument(
        "--datasets",
        nargs="*",
        default=["packet_dataset.csv", "flow_dataset.csv", "cicflow_dataset.csv"],
        help="Dataset files to inspect",
    )
    parser.add_argument("--log", type=Path, default=None, help="Optional log file path")
    parser.add_argument("--json", type=Path, default=None, help="Optional JSON output path")
    return parser


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    dataset_dir = Path(args.path).resolve()
    if not dataset_dir.exists():
        print(f"[FAIL] Dataset directory not found: {dataset_dir}")
        return 1

    setup_logging(args.log)

    reports: List[QualityReport] = []
    datasets: Dict[str, pd.DataFrame] = {}

    for dataset in args.datasets:
        csv_path = dataset_dir / dataset
        try:
            df = load_dataset(csv_path)
            datasets[dataset] = df
            reports.append(analyze_dataset(csv_path, dataset))
        except FileNotFoundError:
            LOGGER.warning("Missing dataset: %s", csv_path)
        except Exception as exc:  # pragma: no cover - defensive
            LOGGER.error("Failed to analyze %s: %s", csv_path, exc)

    inconsistencies = detect_inconsistencies(datasets)
    summarize_reports(reports, inconsistencies, args.json)
    return 0 if reports else 1


if __name__ == "__main__":
    raise SystemExit(main())
