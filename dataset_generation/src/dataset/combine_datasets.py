
#!/usr/bin/env python3
"""
Dataset Combination Script for UKMDDoSDN v1.0

This script combines all CSV files from multiple dataset directories into
three consolidated datasets:
- packet_dataset.csv (all packet_features.csv files)
- flow_dataset.csv (all flow_features.csv files)
- cicflow_dataset.csv (all cicflow_features.csv files)

The script combines datasets without adding any tracking columns.

Usage:
    python3 combine_datasets.py [--path PATH]

Arguments:
    --path PATH    Path to the dataset directory (default: ../main_output)
"""
import pandas as pd
import os
import argparse
import re
from pathlib import Path
import logging
from datetime import datetime
import shutil

def setup_logging(log_path=None):
    """Set up logging configuration."""
    if log_path is None:
        log_path = 'combine_datasets.log'

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_path, mode='w')
        ]
    )
    return logging.getLogger(__name__)

def find_dataset_directories(base_path):
    """Find all dataset directories matching the pattern."""
    datasets = []

    if base_path.exists():
        for item in base_path.iterdir():
            if item.is_dir() and re.match(r'^\d{6}-\d+$', item.name):
                datasets.append(item)

    return sorted(datasets)


def combine_csv_files(datasets, filename, output_name, logger):
    """Combine CSV files of the same type from all datasets."""
    logger.info(f"Combining {filename} files into {output_name}")
    combined_data = []
    total_records = 0

    for dataset_dir in datasets:
        csv_path = dataset_dir / filename

        if csv_path.exists():
            try:
                df = pd.read_csv(csv_path)


                combined_data.append(df)
                records = len(df)
                total_records += records

                logger.info(f"  {dataset_dir.name}: {records:,} records loaded")

            except Exception as e:
                logger.error(f"  Failed to read {csv_path}: {e}")
        else:
            logger.warning(f"  {csv_path} not found - skipping")

    if combined_data:
        final_df = pd.concat(combined_data, ignore_index=True)

        output_path = datasets[0].parent / output_name
        final_df.to_csv(output_path, index=False)

        logger.info(f"  Combined dataset saved: {output_name}")
        logger.info(f"  Total records: {total_records:,}")
        logger.info(f"  Final shape: {final_df.shape}")


        return True, total_records, final_df.shape
    else:
        logger.error(f"  No data found for {filename}")
        return False, 0, (0, 0)

def main():
    """Main function to combine all datasets."""
    parser = argparse.ArgumentParser(description="Combine multiple UKMDDoSDN v1.0 datasets")
    parser.add_argument('--path', default='../main_output',
                       help='Path to dataset directory (default: ../main_output)')
    args = parser.parse_args()

    dataset_base_path = Path(args.path).resolve()

    if not dataset_base_path.exists():
        print(f"Dataset path not found: {dataset_base_path}")
        return 1

    log_path = dataset_base_path / "combine_datasets.log"
    logger = setup_logging(log_path)

    logger.info("=" * 60)
    logger.info("DATASET COMBINATION STARTED")
    logger.info("=" * 60)

    try:
        datasets = find_dataset_directories(dataset_base_path)

        if not datasets:
            logger.error("No dataset directories found!")
            return 1

        logger.info(f"Found {len(datasets)} dataset directories:")
        for dataset in datasets:
            logger.info(f"  - {dataset.name}")

        # File combinations to process (updated for v1.0)
        file_combinations = [
            ("packet_features.csv", "packet_dataset.csv"),
            ("flow_features.csv", "flow_dataset.csv"),
            ("cicflow_features.csv", "cicflow_dataset.csv")
        ]

        results = []
        total_combined_records = 0

        for source_filename, output_filename in file_combinations:
            logger.info(f"\n{'='*50}")
            logger.info(f"Combining {source_filename} files into {output_filename}")
            success, records, shape = combine_csv_files(datasets, source_filename, output_filename, logger)
            results.append((output_filename, success, records, shape))
            if success:
                total_combined_records += records

        logger.info(f"\n{'='*60}")
        logger.info("DATASET COMBINATION SUMMARY")
        logger.info(f"{'='*60}")

        successful_combinations = 0
        for output_name, success, records, shape in results:
            if success:
                successful_combinations += 1
                logger.info(f"SUCCESS {output_name}: {records:,} records, shape {shape}")
            else:
                logger.error(f"FAILED {output_name}: Failed to create")

        logger.info(f"\nTotal files created: {successful_combinations}/3")
        logger.info(f"Total records combined: {total_combined_records:,}")

        if successful_combinations == 3:
            logger.info("All datasets combined successfully!")
            return 0
        else:
            logger.error(f"WARNING: {3 - successful_combinations} dataset(s) failed to combine")
            return 1

    except Exception as e:
        logger.error(f"Error during dataset combination: {e}")
        return 1

if __name__ == "__main__":
    exit(main())