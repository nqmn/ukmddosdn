#!/usr/bin/env python3
"""
Dataset Generation Module for UKMDDoSDN v1.0

This module provides functions for generating packet-level, flow-level, and CICFlow
feature datasets from PCAP files. Designed to be easily imported and called from
other scripts.

Author: UKMDDoSDN v1.0 Framework
"""

import os
import sys
import time
import logging
import pandas as pd
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

def generate_packet_dataset(pcap_files: List[Path],
                          output_dir: Path,
                          output_csv_file: Path,
                          flow_label_timeline: Dict[str, Any],
                          max_workers: int,
                          process_pcaps_function,
                          logger: logging.Logger) -> Tuple[bool, Optional[pd.DataFrame]]:
    """
    Generate packet-level dataset with 30 features.

    Args:
        pcap_files: List of PCAP file paths
        output_dir: Output directory for intermediate files
        output_csv_file: Path for final CSV output
        flow_label_timeline: Timeline for labeling
        max_workers: Number of CPU cores to use
        process_pcaps_function: Function to process PCAPs (passed from main)
        logger: Logger instance

    Returns:
        Tuple of (success, dataframe)
    """
    try:

        logger.info(f"Processing {len(pcap_files)} PCAP files using {max_workers} CPU cores for 30-feature extraction...")

        pcap_start_time = time.time()
        all_labeled_dfs = process_pcaps_function(pcap_files, output_dir, max_workers, flow_label_timeline)
        pcap_processing_time = time.time() - pcap_start_time

        logger.info(f"Parallel 30-feature PCAP processing completed in {pcap_processing_time:.2f} seconds ({pcap_processing_time/60:.2f} minutes)")

        if all_labeled_dfs:
            final_df = pd.concat(all_labeled_dfs, ignore_index=True)
            final_df.to_csv(output_csv_file, index=False)
            logger.info(f"v1.0 30-feature combined labeled CSV generated at: {output_csv_file}")

            if output_csv_file.exists():
                logger.info("v1.0 final 30-feature combined CSV created successfully.")
                try:
                    packet_df = pd.read_csv(output_csv_file)
                    if 'Label_multi' in packet_df.columns:
                        packet_counts = packet_df['Label_multi'].value_counts()
                        logger.info("\n--- v1.0 30-Feature Packet Counts by Class (4-Subnet Topology) ---")
                        for label, count in packet_counts.items():
                            logger.info(f"  {label}: {count} packets")
                    else:
                        logger.warning("Label_multi column not found in packet_features.csv.")
                    return True, packet_df
                except Exception as e:
                    logger.error(f"Error reading or processing packet_features.csv: {e}")
                    return False, None
            else:
                logger.error("Failed to create v1.0 final 30-feature combined CSV.")
                return False, None
        else:
            logger.error("No labeled dataframes were generated. v1.0 final CSV will not be created.")
            return False, None

    except Exception as e:
        logger.error(f"Error in packet dataset generation: {e}")
        return False, None


def generate_flow_dataset(output_flow_csv_file: Path,
                         logger: logging.Logger) -> Tuple[bool, Optional[pd.DataFrame]]:
    """
    Process and clean flow-level dataset.

    Args:
        output_flow_csv_file: Path to flow CSV file
        logger: Logger instance

    Returns:
        Tuple of (success, dataframe)
    """
    try:
        if output_flow_csv_file.exists():
            logger.info(f"v1.0 flow-level dataset generated at: {output_flow_csv_file}")

            flow_df = pd.read_csv(output_flow_csv_file)

            if 'Label_multi' in flow_df.columns:
                original_count = len(flow_df)
                cooldown_count = len(flow_df[flow_df['Label_multi'] == 'cooldown'])

                if cooldown_count > 0:
                    logger.info(f"Filtering out {cooldown_count} cooldown flows for dataset consistency")
                    flow_df = flow_df[flow_df['Label_multi'] != 'cooldown']

                    # Save the filtered dataset back to file
                    flow_df.to_csv(output_flow_csv_file, index=False)
                    logger.info(f"Flow dataset filtered: {original_count} -> {len(flow_df)} flows")

                flow_counts = flow_df['Label_multi'].value_counts()
                logger.info("\n--- v1.0 Flow Feature Counts by Class (4-Subnet Topology) ---")
                for label, count in flow_counts.items():
                    logger.info(f"  {label}: {count} flows")

                return True, flow_df
            else:
                logger.warning("Label_multi column not found in flow_features.csv.")
                return False, None
        else:
            logger.warning("No v1.0 flow-level dataset was generated.")
            return False, None

    except Exception as e:
        logger.error(f"Error reading or processing flow_features.csv: {e}")
        return False, None


def generate_cicflow_dataset(pcap_files: List[Path],
                           output_dir: Path,
                           output_cicflow_csv_file: Path,
                           process_cicflow_function,
                           logger: logging.Logger) -> Tuple[bool, Optional[pd.DataFrame]]:
    """
    Generate CICFlow feature dataset.

    Args:
        pcap_files: List of PCAP file paths
        output_dir: Output directory for intermediate files
        output_cicflow_csv_file: Path for CICFlow CSV output
        process_cicflow_function: Function to process CICFlow (passed from main)
        logger: Logger instance

    Returns:
        Tuple of (success, dataframe)
    """
    try:

        logger.info("Processing CICFlow features...")
        cicflow_start_time = time.time()
        cicflow_df_result = process_cicflow_function(pcap_files, output_dir)
        cicflow_processing_time = time.time() - cicflow_start_time

        if cicflow_df_result is not None:
            logger.info(f"CICFlow processing completed in {cicflow_processing_time:.2f} seconds ({cicflow_processing_time/60:.2f} minutes)")

            # Save the DataFrame to CSV
            try:
                cicflow_df_result.to_csv(output_cicflow_csv_file, index=False)
                logger.info(f"v1.0 CICFlow dataset saved to: {output_cicflow_csv_file}")

                if 'Label_multi' in cicflow_df_result.columns:
                    cicflow_counts = cicflow_df_result['Label_multi'].value_counts()
                    logger.info("\n--- v1.0 CICFlow Feature Counts by Class (4-Subnet Topology) ---")
                    for label, count in cicflow_counts.items():
                        logger.info(f"  {label}: {count} flows")
                else:
                    logger.warning("Label_multi column not found in CICFlow dataset.")
                return True, cicflow_df_result
            except Exception as e:
                logger.error(f"Error saving CICFlow dataset to {output_cicflow_csv_file}: {e}")
                return False, None
        else:
            logger.warning("CICFlow processing failed or skipped (CICFlowMeter not available).")
            return False, None

    except Exception as e:
        logger.error(f"Error in CICFlow dataset generation: {e}")
        return False, None


def generate_all_datasets(pcap_files: List[Path],
                         output_dir: Path,
                         output_csv_file: Path,
                         output_flow_csv_file: Path,
                         output_cicflow_csv_file: Path,
                         flow_label_timeline: Dict[str, Any],
                         max_workers: int,
                         process_pcaps_function,
                         process_cicflow_function,
                         logger: logging.Logger) -> Dict[str, Any]:
    """
    Generate all three datasets: packet-level, flow-level, and CICFlow.

    Args:
        pcap_files: List of PCAP file paths
        output_dir: Output directory for intermediate files
        output_csv_file: Path for packet CSV output
        output_flow_csv_file: Path for flow CSV output
        output_cicflow_csv_file: Path for CICFlow CSV output
        flow_label_timeline: Timeline for labeling
        max_workers: Number of CPU cores to use
        logger: Logger instance

    Returns:
        Dictionary with generation results and dataframes
    """
    results = {
        'packet': {'success': False, 'dataframe': None},
        'flow': {'success': False, 'dataframe': None},
        'cicflow': {'success': False, 'dataframe': None}
    }

    # Generate packet-level dataset
    packet_success, packet_df = generate_packet_dataset(
        pcap_files, output_dir, output_csv_file, flow_label_timeline, max_workers, process_pcaps_function, logger
    )
    results['packet'] = {'success': packet_success, 'dataframe': packet_df}

    # Generate flow-level dataset
    flow_success, flow_df = generate_flow_dataset(output_flow_csv_file, logger)
    results['flow'] = {'success': flow_success, 'dataframe': flow_df}

    # Generate CICFlow dataset
    cicflow_success, cicflow_df = generate_cicflow_dataset(
        pcap_files, output_dir, output_cicflow_csv_file, process_cicflow_function, logger
    )
    results['cicflow'] = {'success': cicflow_success, 'dataframe': cicflow_df}

    return results


def print_generation_summary(results: Dict[str, Any], logger: logging.Logger):
    """
    Print summary of dataset generation results.

    Args:
        results: Results dictionary from generate_all_datasets
        logger: Logger instance
    """
    logger.info("\n" + "=" * 80)
    logger.info("DATASET GENERATION SUMMARY")
    logger.info("=" * 80)

    for dataset_type, result in results.items():
        status = "[OK] SUCCESS" if result['success'] else "[FAIL] FAILED"
        logger.info(f"{dataset_type.upper()} Dataset: {status}")

        if result['success'] and result['dataframe'] is not None:
            df = result['dataframe']
            logger.info(f"  - Rows: {len(df):,}")
            logger.info(f"  - Columns: {len(df.columns)}")
            if 'Label_multi' in df.columns:
                label_counts = df['Label_multi'].value_counts()
                logger.info(f"  - Classes: {', '.join([f'{label}({count})' for label, count in label_counts.items()])}")

    success_count = sum(1 for result in results.values() if result['success'])
    logger.info(f"\nGenerated {success_count}/3 datasets successfully")