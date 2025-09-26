"""Remove duplicate rows from UKMDDoSDN v1.0 combined datasets while keeping backups.

Usage:
    python3 remove_duplicates.py [--version VERSION] [--dry-run]

Arguments:
    --version VERSION    Version directory to process (default: v3)
    --dry-run           Only analyze without making changes
"""
import pandas as pd
import numpy as np
from pathlib import Path
import logging
import argparse
from datetime import datetime

def setup_logging(log_path=None):
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_file, mode='w')
        ]
    )
    return logging.getLogger(__name__)


def remove_duplicates_from_file(file_path, logger, dry_run=False):
    """Remove duplicates from a single CSV file."""
    try:
        logger.info("Processing %s...", file_path.name)
        df = pd.read_csv(file_path)
        original_count = len(df)
        logger.info("  Original records: %s", f"{original_count:,}")

        duplicate_count = df.duplicated().sum()
        logger.info("  Duplicates found: %s", f"{duplicate_count:,}")

        if duplicate_count == 0:
            logger.info("  [OK] No duplicates found - skipping %s", file_path.name)
            return True, original_count, original_count, 0

        if dry_run:
            cleaned_count = original_count - duplicate_count
            logger.info("  DRY RUN: Would remove %s duplicates", f"{duplicate_count:,}")
            logger.info("  DRY RUN: Would result in %s records", f"{cleaned_count:,}")
            return True, original_count, cleaned_count, duplicate_count

        backup_path = file_path.with_suffix('.csv.backup_duplicates')
        if not backup_path.exists():
            df.to_csv(backup_path, index=False)
            logger.info("  [DIR] Backup created: %s", backup_path.name)
        else:
            logger.info("  [DIR] Backup already exists: %s", backup_path.name)

        df_clean = df.drop_duplicates(keep='first')
        cleaned_count = len(df_clean)
        df_clean.to_csv(file_path, index=False)

        logger.info("  [OK] Cleaned records: %s", f"{cleaned_count:,}")
        logger.info("  [DELETE] Removed duplicates: %s", f"{duplicate_count:,}")
        logger.info("  [SAVE] Updated file: %s", file_path.name)

        df_verify = pd.read_csv(file_path)
        remaining_duplicates = df_verify.duplicated().sum()
        if remaining_duplicates == 0:
            logger.info("  [OK] Verification passed - no duplicates remain")
        else:
            logger.warning("  [WARN] Verification warning - %s duplicates still found", remaining_duplicates)

        return True, original_count, cleaned_count, duplicate_count

    except Exception as exc:  # pragma: no cover - defensive
        logger.error("  [FAIL] Error processing %s: %s", file_path.name, exc)
        return False, 0, 0, 0

def main():
    """Main function to remove duplicates from all combined datasets."""
    parser = argparse.ArgumentParser(description="Remove duplicate rows from combined datasets")
    parser.add_argument('--path', default='../main_output/v3', help='Path to dataset directory (default: ../main_output/v3)')
    parser.add_argument('--dry-run', action='store_true', help='Only analyze without making changes')

    args = parser.parse_args()

    dataset_path = Path(args.path)
    if not dataset_path.exists():
        print(f"[FAIL] Error: Dataset directory not found: {dataset_path}")
        return 1

    log_path = dataset_path / "remove_duplicates.log"
    logger = setup_logging(log_path)

    operation = "DRY RUN - " if args.dry_run else ""
    logger.info(f"[CLEAN] {operation}Remove Duplicates from Combined Datasets")
    logger.info(f"[DIR] Dataset directory: {dataset_path.absolute()}")

    logger.info("=" * 60)
    logger.info(f"{operation.upper()}DUPLICATE REMOVAL STARTED")
    logger.info("=" * 60)

    files_to_process = [
        "packet_dataset.csv",
        "flow_dataset.csv", 
        "cicflow_dataset.csv"
    ]

    results = []
    total_original = 0
    total_cleaned = 0
    total_removed = 0

    for filename in files_to_process:
        file_path = dataset_path / filename

        if not file_path.exists():
            logger.warning(f"[WARN]  File not found: {filename}")
            continue

        logger.info(f"\n{'='*50}")
        success, original, cleaned, removed = remove_duplicates_from_file(file_path, logger, dry_run=args.dry_run)

        results.append({
            'filename': filename,
            'success': success,
            'original_count': original,
            'cleaned_count': cleaned,
            'removed_count': removed
        })

        if success:
            total_original += original
            total_cleaned += cleaned
            total_removed += removed

    logger.info(f"\n{'='*60}")
    logger.info(f"{operation.upper()}DUPLICATE REMOVAL SUMMARY")
    logger.info(f"{'='*60}")

    successful_files = 0
    for result in results:
        if result['success']:
            successful_files += 1
            status_icon = "[OK]" if not args.dry_run else "[NOTES]"
            logger.info(f"{status_icon} {result['filename']}:")
            logger.info(f"   Original: {result['original_count']:,}")
            logger.info(f"   Cleaned:  {result['cleaned_count']:,}")
            action = "Removed" if not args.dry_run else "Would remove"
            logger.info(f"   {action}:  {result['removed_count']:,}")
        else:
            logger.error(f"[FAIL] {result['filename']}: Failed to process")

    logger.info(f"\n[STATS] TOTALS:")
    logger.info(f"   Files processed: {successful_files}/{len(files_to_process)}")
    logger.info(f"   Original records: {total_original:,}")
    logger.info(f"   Cleaned records:  {total_cleaned:,}")
    action = "removed" if not args.dry_run else "would remove"
    logger.info(f"   Total {action}:    {total_removed:,}")

    if total_removed > 0:
        reduction_pct = (total_removed / total_original) * 100
        logger.info(f"   Data reduction:   {reduction_pct:.2f}%")

    if total_removed == 0:
        logger.info("[DONE] No duplicates found - datasets are clean!")
        return 0
    elif successful_files == len(files_to_process):
        if args.dry_run:
            logger.info(f"[NOTES] {operation}Analysis completed successfully!")
        else:
            logger.info("[DONE] All datasets cleaned successfully!")
        return 0
    else:
        failed_count = len(files_to_process) - successful_files
        logger.error(f"[WARN]  {failed_count} file(s) failed to process")
        return 1

if __name__ == "__main__":
    exit(main())
