"""Split UKMDDoSDN v1.0 combined CSV files into <= 100 MB chunks suitable for GitHub."""

from __future__ import annotations

import argparse
import csv
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Iterable, TextIO


DEFAULT_DATASET_FILES: tuple[str, ...] = (
    "packet_dataset.csv",
    "flow_dataset.csv",
    "cicflow_dataset.csv",
)


def setup_logging(log_path: Path | None = None) -> logging.Logger:
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_path:
        handlers.append(logging.FileHandler(log_path, mode="w", encoding="utf-8"))

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=handlers,
    )
    return logging.getLogger("split_datasets")


def get_file_size_mb(file_path: Path) -> float:
    return file_path.stat().st_size / (1024 * 1024)


def estimate_rows_per_chunk(csv_file: Path, max_size_mb: int) -> int:
    file_size_mb = get_file_size_mb(csv_file)
    if file_size_mb == 0:
        return 0

    with csv_file.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.reader(handle)
        next(reader, None)  # Skip header
        total_rows = sum(1 for _ in reader)

    if total_rows == 0:
        return 0

    rows_per_mb = total_rows / file_size_mb
    # Leave a safety margin so we do not exceed the target chunk size
    estimated_rows = int(rows_per_mb * max_size_mb * 0.9)
    return max(1, estimated_rows)


def split_csv_file(input_file: Path, output_dir: Path, max_size_mb: int, logger: logging.Logger) -> bool:
    if not input_file.exists():
        logger.error("Input file not found: %s", input_file)
        return False

    file_size_mb = get_file_size_mb(input_file)
    logger.info("Processing %s (%.1f MB)", input_file.name, file_size_mb)

    if file_size_mb <= max_size_mb:
        logger.info("File already under %s MB - skipping split", max_size_mb)
        return True

    rows_per_chunk = estimate_rows_per_chunk(input_file, max_size_mb)
    if rows_per_chunk <= 0:
        logger.warning("Could not estimate rows per chunk for %s", input_file.name)
        return False

    output_dir.mkdir(parents=True, exist_ok=True)
    base_name = input_file.stem

    try:
        with input_file.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.reader(handle)
            header = next(reader)

            chunk_index = 1
            rows_written = 0
            outfile: Path | None = None
            writer: csv.writer | None = None
            current_chunk_path: Path | None = None

            def open_chunk(index: int) -> tuple[csv.writer, Path, TextIO]:
                chunk_path = output_dir / f"{base_name}_part_{index:03d}.csv"
                chunk_file = chunk_path.open("w", encoding="utf-8", newline="")
                chunk_writer = csv.writer(chunk_file)
                chunk_writer.writerow(header)
                return chunk_writer, chunk_path, chunk_file

            writer, current_chunk_path, outfile_handle = open_chunk(chunk_index)

            for row in reader:
                writer.writerow(row)
                rows_written += 1

                if rows_written >= rows_per_chunk:
                    outfile_handle.close()
                    actual_size = get_file_size_mb(current_chunk_path)
                    logger.info("  Chunk %03d: %s rows, %.1f MB", chunk_index, rows_written, actual_size)

                    chunk_index += 1
                    rows_written = 0
                    writer, current_chunk_path, outfile_handle = open_chunk(chunk_index)

            outfile_handle.close()
            if current_chunk_path is not None:
                actual_size = get_file_size_mb(current_chunk_path)
                logger.info("  Chunk %03d: %s rows, %.1f MB", chunk_index, rows_written, actual_size)

    except Exception as exc:  # pragma: no cover - runtime safeguard
        logger.error("Error splitting %s: %s", input_file, exc)
        return False

    logger.info("Finished splitting %s", input_file.name)
    return True


def create_chunk_info_file(dataset_path: Path, chunk_dir: Path, logger: logging.Logger) -> None:
    chunk_dir.mkdir(parents=True, exist_ok=True)
    info_path = chunk_dir / "README_CHUNKS.md"
    info_content = f"""# Chunked Datasets\n\nGenerated from {dataset_path} on {datetime.now():%Y-%m-%d %H:%M:%S}.\nEach chunk includes the CSV header and stays under 100 MB so the files can be committed to GitHub.\n\n## Reconstructing the original file\n\n`ash\nhead -n 1 {chunk_dir.name}_part_001.csv > combined.csv\ntail -n +2 -q {chunk_dir.name}_part_*.csv >> combined.csv\n`\n\nRepeat the command for each dataset (packet, flow, cicflow).\n"""
    info_path.write_text(info_content, encoding="utf-8")
    logger.info("Created chunk info file at %s", info_path)


def iter_dataset_files(root: Path, filenames: Iterable[str]) -> Iterable[Path]:
    for name in filenames:
        candidate = root / name
        if candidate.exists():
            yield candidate


def main() -> None:
    parser = argparse.ArgumentParser(description="Split combined dataset CSVs into GitHub-friendly chunks")
    parser.add_argument("--path", default="../main_output/v4", help="Path to dataset directory")
    parser.add_argument("--chunk-size", type=int, default=95, help="Maximum chunk size in MB")
    parser.add_argument("--log", type=Path, default=Path("split_datasets.log"), help="Log file path")
    args = parser.parse_args()

    dataset_root = Path(args.path).resolve()
    logger = setup_logging(args.log)

    if not dataset_root.exists():
        logger.error("Dataset directory does not exist: %s", dataset_root)
        raise SystemExit(1)

    logger.info("Splitting datasets in %s", dataset_root)

    chunk_root = dataset_root / "chunks"
    chunk_root.mkdir(exist_ok=True)

    for dataset_file in iter_dataset_files(dataset_root, DEFAULT_DATASET_FILES):
        output_dir = chunk_root / dataset_file.stem
        success = split_csv_file(dataset_file, output_dir, args.chunk_size, logger)
        if success:
            create_chunk_info_file(dataset_file.parent, output_dir, logger)

    logger.info("Done")


if __name__ == "__main__":
    main()

