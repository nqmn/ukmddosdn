"""
Dataset Combiner Module for UKMDDoSDN Framework

This module provides functionality to combine CSV datasets from multiple
experimental runs into unified datasets for analysis and machine learning.

Author: UKMDDoSDN Framework
"""

import re
import logging
import subprocess
import os
from pathlib import Path
from typing import List, Tuple, Optional
import pandas as pd


class DatasetCombiner:
    """Class for combining CSV datasets from multiple experimental runs."""

    def __init__(self, output_base: Path, logger: Optional[logging.Logger] = None):
        """
        Initialize the DatasetCombiner.

        Args:
            output_base: Base directory containing dataset subdirectories
            logger: Optional logger instance for detailed logging
        """
        self.output_base = Path(output_base)
        self.logger = logger or self._setup_default_logger()

        # Standard file combinations for UKMDDoSDN datasets
        self.file_combinations = [
            ("packet_features.csv", "packet_dataset.csv"),
            ("flow_features.csv", "flow_dataset.csv"),
            ("cicflow_features.csv", "cicflow_dataset.csv")
        ]

        # Standard PCAP file combinations for UKMDDoSDN datasets
        self.pcap_combinations = [
            ("normal.pcap", "normal_combined.pcap"),
            ("syn_flood.pcap", "syn_flood_combined.pcap"),
            ("udp_flood.pcap", "udp_flood_combined.pcap"),
            ("icmp_flood.pcap", "icmp_flood_combined.pcap")
        ]

    def _setup_default_logger(self) -> logging.Logger:
        """Setup default logger if none provided."""
        logger = logging.getLogger(__name__)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            logger.setLevel(logging.INFO)
        return logger

    def find_dataset_directories(self) -> List[Path]:
        """
        Find all dataset directories matching the expected pattern.

        Returns:
            List of dataset directory paths sorted by name
        """
        datasets = []
        if self.output_base.exists():
            for item in self.output_base.iterdir():
                if item.is_dir() and re.match(r'^\d{6}-\d+$', item.name):
                    datasets.append(item)

        return sorted(datasets)

    def combine_csv_files(self, datasets: List[Path], source_filename: str,
                         output_filename: str) -> Tuple[bool, int, Tuple[int, int]]:
        """
        Combine CSV files of the same type from all dataset directories.

        Args:
            datasets: List of dataset directory paths
            source_filename: Name of source CSV file to combine
            output_filename: Name of output combined CSV file

        Returns:
            Tuple of (success, total_records, final_shape)
        """
        self.logger.info(f"Combining {source_filename} files into {output_filename}")
        combined_data = []
        total_records = 0

        for dataset_dir in datasets:
            csv_path = dataset_dir / source_filename

            if csv_path.exists():
                try:
                    df = pd.read_csv(csv_path)
                    combined_data.append(df)
                    records = len(df)
                    total_records += records
                    self.logger.info(f"  {dataset_dir.name}: {records:,} records loaded")
                except Exception as e:
                    self.logger.error(f"  Failed to read {csv_path}: {e}")
            else:
                self.logger.warning(f"  {csv_path} not found - skipping")

        if combined_data:
            final_df = pd.concat(combined_data, ignore_index=True)
            output_path = self.output_base / output_filename
            final_df.to_csv(output_path, index=False)
            self.logger.info(f"  Combined dataset saved: {output_filename}")
            self.logger.info(f"  Total records: {total_records:,}")
            self.logger.info(f"  Final shape: {final_df.shape}")
            return True, total_records, final_df.shape
        else:
            self.logger.error(f"  No data found for {source_filename}")
            return False, 0, (0, 0)

    def combine_pcap_files(self, datasets: List[Path], source_filename: str,
                          output_filename: str) -> Tuple[bool, int, int]:
        """
        Combine PCAP files of the same type from all dataset directories using mergecap.

        Args:
            datasets: List of dataset directory paths
            source_filename: Name of source PCAP file to combine
            output_filename: Name of output combined PCAP file

        Returns:
            Tuple of (success, total_files_combined, total_size_mb)
        """
        self.logger.info(f"Combining {source_filename} files into {output_filename}")

        # Collect all PCAP files that exist
        pcap_files = []
        total_size_bytes = 0

        for dataset_dir in datasets:
            pcap_path = dataset_dir / source_filename

            if pcap_path.exists():
                try:
                    file_size = os.path.getsize(pcap_path)
                    pcap_files.append(str(pcap_path))
                    total_size_bytes += file_size
                    self.logger.info(f"  {dataset_dir.name}: {file_size / (1024*1024):.2f} MB")
                except Exception as e:
                    self.logger.error(f"  Failed to read {pcap_path}: {e}")
            else:
                self.logger.warning(f"  {pcap_path} not found - skipping")

        if not pcap_files:
            self.logger.error(f"  No PCAP files found for {source_filename}")
            return False, 0, 0

        if len(pcap_files) == 1:
            # Only one file, just copy it
            import shutil
            output_path = self.output_base / output_filename
            try:
                shutil.copy2(pcap_files[0], output_path)
                self.logger.info(f"  Single PCAP file copied: {output_filename}")
                return True, 1, int(total_size_bytes / (1024*1024))
            except Exception as e:
                self.logger.error(f"  Failed to copy PCAP file: {e}")
                return False, 0, 0

        # Multiple files, use mergecap to combine
        output_path = self.output_base / output_filename

        try:
            # Use mergecap to combine PCAP files chronologically
            cmd = ['mergecap', '-w', str(output_path)] + pcap_files

            self.logger.info(f"  Running mergecap with {len(pcap_files)} files...")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                final_size = os.path.getsize(output_path)
                self.logger.info(f"  Combined PCAP saved: {output_filename}")
                self.logger.info(f"  Files combined: {len(pcap_files)}")
                self.logger.info(f"  Total size: {final_size / (1024*1024):.2f} MB")
                return True, len(pcap_files), int(final_size / (1024*1024))
            else:
                self.logger.error(f"  mergecap failed: {result.stderr}")
                return False, 0, 0

        except subprocess.TimeoutExpired:
            self.logger.error(f"  mergecap timeout for {source_filename}")
            return False, 0, 0
        except FileNotFoundError:
            self.logger.error("  mergecap not found. Please install Wireshark tools.")
            return False, 0, 0
        except Exception as e:
            self.logger.error(f"  Error combining PCAP files: {e}")
            return False, 0, 0

    def combine_all_datasets(self, include_pcap: bool = True) -> bool:
        """
        Combine all standard UKMDDoSDN datasets and optionally PCAP files.

        Args:
            include_pcap: Whether to also combine PCAP files (default: True)

        Returns:
            True if all datasets combined successfully, False otherwise
        """
        print(f"\n[COMBINE] Starting dataset combination...")

        # Setup logging to file
        log_path = self.output_base / "combine_datasets.log"
        if log_path.exists():
            log_path.unlink()

        file_handler = logging.FileHandler(log_path, mode='w')
        file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(file_handler)

        try:
            # Find dataset directories
            datasets = self.find_dataset_directories()

            if not datasets:
                print("[COMBINE] No dataset directories found!")
                return False

            print(f"[COMBINE] Found {len(datasets)} dataset directories:")
            for dataset in datasets:
                print(f"[COMBINE]   - {dataset.name}")

            # Process all CSV file combinations
            csv_results = []
            total_combined_records = 0

            for source_filename, output_filename in self.file_combinations:
                print(f"[COMBINE] Combining {source_filename} files...")
                success, records, shape = self.combine_csv_files(
                    datasets, source_filename, output_filename
                )
                csv_results.append((output_filename, success, records, shape))
                if success:
                    total_combined_records += records

            # Process PCAP file combinations if requested
            pcap_results = []
            total_combined_pcaps = 0
            total_pcap_size = 0

            if include_pcap:
                print(f"\n[COMBINE] Starting PCAP file combination...")
                for source_filename, output_filename in self.pcap_combinations:
                    print(f"[COMBINE] Combining {source_filename} files...")
                    success, files_count, size_mb = self.combine_pcap_files(
                        datasets, source_filename, output_filename
                    )
                    pcap_results.append((output_filename, success, files_count, size_mb))
                    if success:
                        total_combined_pcaps += files_count
                        total_pcap_size += size_mb

            # Generate summary
            return self._print_summary(csv_results, total_combined_records, pcap_results, total_combined_pcaps, total_pcap_size)

        finally:
            # Remove file handler to avoid duplicate logs
            if file_handler in self.logger.handlers:
                self.logger.removeHandler(file_handler)
                file_handler.close()

    def _print_summary(self, csv_results: List[Tuple[str, bool, int, Tuple[int, int]]],
                      total_combined_records: int,
                      pcap_results: List[Tuple[str, bool, int, int]] = None,
                      total_combined_pcaps: int = 0,
                      total_pcap_size: int = 0) -> bool:
        """Print combination summary and return success status."""
        print(f"\n[COMBINE] Dataset combination summary:")

        # CSV Results
        successful_csv = 0
        print(f"\n[COMBINE] CSV Datasets:")
        for output_name, success, records, shape in csv_results:
            if success:
                successful_csv += 1
                print(f"[COMBINE]   SUCCESS {output_name}: {records:,} records, shape {shape}")
            else:
                print(f"[COMBINE]   FAILED {output_name}: Failed to create")

        print(f"[COMBINE] CSV files created: {successful_csv}/{len(self.file_combinations)}")
        print(f"[COMBINE] Total CSV records combined: {total_combined_records:,}")

        # PCAP Results
        successful_pcap = 0
        if pcap_results:
            print(f"\n[COMBINE] PCAP Files:")
            for output_name, success, files_count, size_mb in pcap_results:
                if success:
                    successful_pcap += 1
                    print(f"[COMBINE]   SUCCESS {output_name}: {files_count} files, {size_mb} MB")
                else:
                    print(f"[COMBINE]   FAILED {output_name}: Failed to create")

            print(f"[COMBINE] PCAP files created: {successful_pcap}/{len(self.pcap_combinations)}")
            print(f"[COMBINE] Total PCAP size combined: {total_pcap_size} MB")

        # Overall Success
        csv_success = successful_csv == len(self.file_combinations)
        pcap_success = not pcap_results or successful_pcap == len(self.pcap_combinations)

        if csv_success and pcap_success:
            print("\n[COMBINE] All datasets and PCAP files combined successfully!")
            return True
        else:
            failed_csv = len(self.file_combinations) - successful_csv if not csv_success else 0
            failed_pcap = len(self.pcap_combinations) - successful_pcap if pcap_results and not pcap_success else 0

            if failed_csv > 0:
                print(f"\n[COMBINE] WARNING: {failed_csv} CSV dataset(s) failed to combine")
            if failed_pcap > 0:
                print(f"[COMBINE] WARNING: {failed_pcap} PCAP file(s) failed to combine")
            return False


def combine_datasets(output_base: Path, logger: Optional[logging.Logger] = None, include_pcap: bool = True) -> bool:
    """
    Convenience function to combine datasets using the DatasetCombiner class.

    Args:
        output_base: Base directory containing dataset subdirectories
        logger: Optional logger instance
        include_pcap: Whether to also combine PCAP files (default: True)

    Returns:
        True if all datasets combined successfully, False otherwise
    """
    combiner = DatasetCombiner(output_base, logger)
    return combiner.combine_all_datasets(include_pcap)