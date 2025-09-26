"""Analyze the timeline alignment for the three UKMDDoSDN v1.0 combined datasets:
- packet_dataset.csv
- flow_dataset.csv
- cicflow_dataset.csv

Ensures proper synchronization of attack phases across all combined dataset types.

Usage:
    python3 analyze_timeline_v3.py [--version VERSION]

Arguments:
    --version VERSION    Version directory to analyze (default: v3)
"""
import csv
import sys
import os
import argparse
import logging
from pathlib import Path
from datetime import datetime
from collections import defaultdict

def parse_timestamp(timestamp_str):
    """Parse timestamp from either Unix epoch (float) or datetime string format."""
    try:
        return float(timestamp_str)
    except ValueError:
        try:
            if ' ' in timestamp_str:
                dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
            else:
                dt = datetime.fromisoformat(timestamp_str)
            return dt.timestamp()
        except (ValueError, AttributeError):
            try:
                dt = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
                return dt.timestamp()
            except ValueError:
                raise ValueError(f"Unable to parse timestamp: {timestamp_str}")

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

def read_csv_timeline(csv_file, timestamp_col, label_col, logger):
    """Read CSV file and extract timeline information for each attack type."""
    if not Path(csv_file).exists():
        logger.error(f"File not found: {csv_file}")
        return {}

    timeline_data = defaultdict(list)

    try:
        with open(csv_file, 'r') as f:
            reader = csv.reader(f)
            header = next(reader)

            if timestamp_col == "auto":
                if 'timestamp' in header:
                    timestamp_col = header.index('timestamp')
                else:
                    logger.error(f"No 'timestamp' column found in {csv_file.name}")
                    return {}

            if label_col == -1:
                if 'Label_multi' in header:
                    label_col = header.index('Label_multi')
                else:
                    label_col = len(header) - 2

            logger.info(f"Reading {csv_file.name} - timestamp col: {timestamp_col} ({header[timestamp_col]}), label col: {label_col} ({header[label_col] if label_col < len(header) else 'UNKNOWN'})")
            logger.info(f"Total columns: {len(header)}")

            for row_num, row in enumerate(reader):
                if len(row) > max(timestamp_col, label_col):
                    try:
                        timestamp = parse_timestamp(row[timestamp_col])
                        label = row[label_col]
                        if label.strip():
                            timeline_data[label].append(timestamp)
                    except (ValueError, IndexError) as e:
                        if row_num < 10:
                            logger.warning(f"Row {row_num}: {e}")

    except Exception as e:
        logger.error(f"Error reading {csv_file}: {e}")
        return {}

    attack_timeline = {}
    for label, timestamps in timeline_data.items():
        if timestamps:
            attack_timeline[label] = {
                'start': min(timestamps),
                'end': max(timestamps),
                'duration': max(timestamps) - min(timestamps),
                'count': len(timestamps)
            }

    logger.info(f"Found {len(attack_timeline)} attack types with {sum(len(ts) for ts in timeline_data.values())} total records")
    return attack_timeline

def format_timestamp(timestamp):
    """Convert timestamp to readable format."""

def format_duration(duration):
    """Format duration in seconds with 1 decimal place."""

def analyze_three_way_coverage(packet_timeline, flow_timeline, cicflow_timeline):
    """Analyze coverage and alignment between all three timeline types."""
    analysis = {}

    for attack in sorted(all_attacks):
        packet_data = packet_timeline.get(attack)
        flow_data = flow_timeline.get(attack)
        cicflow_data = cicflow_timeline.get(attack)

        present_count = sum([bool(packet_data), bool(flow_data), bool(cicflow_data)])

        if packet_data and flow_data and cicflow_data:
            overlap_start = max(packet_data['start'], flow_data['start'], cicflow_data['start'])
            overlap_end = min(packet_data['end'], flow_data['end'], cicflow_data['end'])
            overlap_duration = max(0, overlap_end - overlap_start)

            packet_flow_gap = abs(packet_data['start'] - flow_data['start'])
            packet_cicflow_gap = abs(packet_data['start'] - cicflow_data['start'])
            flow_cicflow_gap = abs(flow_data['start'] - cicflow_data['start'])
            max_gap = max(packet_flow_gap, packet_cicflow_gap, flow_cicflow_gap)

            if overlap_duration < 1:
                status = "[FAIL] POOR 3-WAY OVERLAP"
            elif max_gap > 30:
                status = "[WARN]  LARGE TIMING GAPS"
            elif overlap_duration > min(packet_data['duration'], flow_data['duration'], cicflow_data['duration']) * 0.8:
                status = "[OK] EXCELLENT 3-WAY MATCH"
            else:
                status = "[OK] GOOD 3-WAY OVERLAP"

        elif present_count == 2:
            overlap_duration = 0
            max_gap = 0
            if packet_data and flow_data:
                overlap_start = max(packet_data['start'], flow_data['start'])
                overlap_end = min(packet_data['end'], flow_data['end'])
                overlap_duration = max(0, overlap_end - overlap_start)
                max_gap = abs(packet_data['start'] - flow_data['start'])
            status = f"[WARN]  PARTIAL COVERAGE ({present_count}/3)"

        elif present_count == 1:
            overlap_duration = 0
            max_gap = 0
            status = f"[FAIL] SINGLE SOURCE ONLY ({present_count}/3)"
        else:
            overlap_duration = 0
            max_gap = 0
            status = "[FAIL] NO DATA FOUND"

        analysis[attack] = {
            'packet_data': packet_data,
            'flow_data': flow_data,
            'cicflow_data': cicflow_data,
            'present_count': present_count,
            'overlap_duration': overlap_duration,
            'max_gap': max_gap,
            'status': status
        }

    return analysis

def print_three_way_timeline_table(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger):
    """Print a formatted three-way timeline comparison table."""
    logger.info("[STATS] THREE-WAY TIMELINE ANALYSIS RESULTS")
    logger.info("="*120)

    header = f"{'Attack Type':<12} {'Packet Timeline':<25} {'Flow Timeline':<25} {'CICFlow Timeline':<25} {'3-Way Status':<25}"
    logger.info(header)
    logger.info("-" * 120)

    for attack in sorted(analysis.keys()):
        data = analysis[attack]
        packet_data = data['packet_data']
        flow_data = data['flow_data']
        cicflow_data = data['cicflow_data']

        if packet_data:
            packet_info = f"{format_duration(packet_data['duration'])} ({packet_data['count']} entries)"
        else:
            packet_info = "MISSING"

        if flow_data:
            flow_info = f"{format_duration(flow_data['duration'])} ({flow_data['count']} entries)"
        else:
            flow_info = "MISSING"

        if cicflow_data:
            cicflow_info = f"{format_duration(cicflow_data['duration'])} ({cicflow_data['count']} entries)"
        else:
            cicflow_info = "MISSING"

        row = f"{attack:<12} {packet_info:<25} {flow_info:<25} {cicflow_info:<25} {data['status']:<25}"
        logger.info(row)

def print_detailed_three_way_timing(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger):
    """Print detailed timing information for all three datasets."""
    logger.info("[CLOCK] DETAILED THREE-WAY TIMING INFORMATION")
    logger.info("="*100)

    for attack in sorted(analysis.keys()):
        data = analysis[attack]
        packet_data = data['packet_data']
        flow_data = data['flow_data']
        cicflow_data = data['cicflow_data']

        logger.info(f"\n[PIN] {attack.upper()}:")

        if packet_data:
            logger.info(f"   Packet:  {format_timestamp(packet_data['start'])} - {format_timestamp(packet_data['end'])} ({format_duration(packet_data['duration'])})")
        else:
            logger.info(f"   Packet:  MISSING")

        if flow_data:
            logger.info(f"   Flow:    {format_timestamp(flow_data['start'])} - {format_timestamp(flow_data['end'])} ({format_duration(flow_data['duration'])})")
        else:
            logger.info(f"   Flow:    MISSING")

        if cicflow_data:
            logger.info(f"   CICFlow: {format_timestamp(cicflow_data['start'])} - {format_timestamp(cicflow_data['end'])} ({format_duration(cicflow_data['duration'])})")
        else:
            logger.info(f"   CICFlow: MISSING")

        if data['present_count'] >= 2:
            gaps = []
            if packet_data and flow_data:
                gap = abs(packet_data['start'] - flow_data['start'])
                gaps.append(f"Packet-Flow: +/-{gap:.1f}s")
            if packet_data and cicflow_data:
                gap = abs(packet_data['start'] - cicflow_data['start'])
                gaps.append(f"Packet-CICFlow: +/-{gap:.1f}s")
            if flow_data and cicflow_data:
                gap = abs(flow_data['start'] - cicflow_data['start'])
                gaps.append(f"Flow-CICFlow: +/-{gap:.1f}s")

            if gaps:
                logger.info(f"   Gaps:    {', '.join(gaps)}")

def print_three_way_summary_statistics(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger):
    """Print summary statistics for three-way analysis."""
    excellent_matches = len([a for a in analysis.values() if "EXCELLENT 3-WAY MATCH" in a['status']])
    good_matches = len([a for a in analysis.values() if "GOOD 3-WAY OVERLAP" in a['status']])
    partial_coverage = len([a for a in analysis.values() if "PARTIAL COVERAGE" in a['status']])
    single_source = len([a for a in analysis.values() if "SINGLE SOURCE ONLY" in a['status']])
    poor_overlap = len([a for a in analysis.values() if "POOR 3-WAY OVERLAP" in a['status'] or "LARGE TIMING GAPS" in a['status']])

    logger.info("\n" + "="*80)
    logger.info("[CHART] THREE-WAY SUMMARY STATISTICS")
    logger.info("="*80)
    logger.info(f"Total attack types: {total_attacks}")
    logger.info(f"[OK] Excellent 3-way match: {excellent_matches}")
    logger.info(f"[OK] Good 3-way alignment: {good_matches}")
    logger.info(f"[WARN]  Partial coverage (2/3): {partial_coverage}")
    logger.info(f"[FAIL] Single source only (1/3): {single_source}")
    logger.info(f"[FAIL] Poor alignment/gaps: {poor_overlap}")

    full_coverage = excellent_matches + good_matches
    coverage_score = (full_coverage / total_attacks * 100) if total_attacks > 0 else 0

    logger.info(f"\n[TARGET] Full Coverage Score: {coverage_score:.1f}% ({full_coverage}/{total_attacks})")

    packet_coverage = len([a for a in analysis.values() if a['packet_data'] is not None])
    flow_coverage = len([a for a in analysis.values() if a['flow_data'] is not None])
    cicflow_coverage = len([a for a in analysis.values() if a['cicflow_data'] is not None])

    logger.info(f"\n[STATS] Individual Dataset Coverage:")
    logger.info(f"   Packet dataset:  {packet_coverage}/{total_attacks} ({packet_coverage/total_attacks*100:.1f}%)")
    logger.info(f"   Flow dataset:    {flow_coverage}/{total_attacks} ({flow_coverage/total_attacks*100:.1f}%)")
    logger.info(f"   CICFlow dataset: {cicflow_coverage}/{total_attacks} ({cicflow_coverage/total_attacks*100:.1f}%)")

    if coverage_score >= 90:
        logger.info("[DONE] EXCELLENT: Three-way timeline alignment is outstanding!")
    elif coverage_score >= 70:
        logger.info("[THUMBSUP] GOOD: Three-way timeline alignment is solid with minor gaps.")
    elif coverage_score >= 50:
        logger.info("[WARN]  FAIR: Three-way timeline alignment needs improvement.")
    else:
        logger.info("[FAIL] POOR: Three-way timeline alignment has major issues requiring attention.")

def suggest_three_way_improvements(analysis, packet_timeline, flow_timeline, cicflow_timeline, logger):
    """Suggest improvements based on three-way analysis results."""
    logger.info("[IDEA] THREE-WAY IMPROVEMENT SUGGESTIONS")
    logger.info("="*80)

    missing_in_packet = [attack for attack, data in analysis.items() if data['packet_data'] is None]
    missing_in_flow = [attack for attack, data in analysis.items() if data['flow_data'] is None]
    missing_in_cicflow = [attack for attack, data in analysis.items() if data['cicflow_data'] is None]
    large_gaps = [attack for attack, data in analysis.items() if data['max_gap'] > 30]

    if missing_in_packet:
        logger.info(f"[TOOLS] Packet data missing for: {', '.join(missing_in_packet)}")
        logger.info("   Solution: Check packet capture timing and PCAP processing")

    if missing_in_flow:
        logger.info(f"[TOOLS] Flow data missing for: {', '.join(missing_in_flow)}")
        logger.info("   Solution: Verify flow collection duration and timing")

    if missing_in_cicflow:
        logger.info(f"[TOOLS] CICFlow data missing for: {', '.join(missing_in_cicflow)}")
        logger.info("   Solution: Check CICFlow processing and feature extraction")

    if large_gaps:
        logger.info(f"[TOOLS] Large timing gaps (>30s) for: {', '.join(large_gaps)}")
        logger.info("   Solution: Synchronize data collection start times across all three sources")

    if packet_timeline and flow_timeline and cicflow_timeline:
        packet_span = max([data['end'] for data in packet_timeline.values()]) - min([data['start'] for data in packet_timeline.values()])
        flow_span = max([data['end'] for data in flow_timeline.values()]) - min([data['start'] for data in flow_timeline.values()])
        cicflow_span = max([data['end'] for data in cicflow_timeline.values()]) - min([data['start'] for data in cicflow_timeline.values()])

        logger.info(f"\n[STATS] Data Collection Span Analysis:")
        logger.info(f"   Packet data spans:  {packet_span:.1f}s")
        logger.info(f"   Flow data spans:    {flow_span:.1f}s")  
        logger.info(f"   CICFlow data spans: {cicflow_span:.1f}s")

        max_span = max(packet_span, flow_span, cicflow_span)
        if packet_span < max_span - 10:
            logger.info(f"   [WARN]  Packet collection {max_span - packet_span:.1f}s shorter than needed")
        if flow_span < max_span - 10:
            logger.info(f"   [WARN]  Flow collection {max_span - flow_span:.1f}s shorter than needed")
        if cicflow_span < max_span - 10:
            logger.info(f"   [WARN]  CICFlow collection {max_span - cicflow_span:.1f}s shorter than needed")

def analyze_combined_datasets(dataset_path, logger):
    """Analyze timeline for the three combined dataset files."""
    logger.info(f"ANALYZING COMBINED DATASETS IN: {dataset_path.name}")
    logger.info(f"{'='*80}")

    packet_csv = dataset_path / "packet_dataset.csv"
    flow_csv = dataset_path / "flow_dataset.csv"
    cicflow_csv = dataset_path / "cicflow_dataset.csv"

    logger.info(f"[DIR] Dataset directory: {dataset_path.absolute()}")
    logger.info(f"[DOC] Packet dataset: {packet_csv}")
    logger.info(f"[DOC] Flow dataset: {flow_csv}")
    logger.info(f"[DOC] CICFlow dataset: {cicflow_csv}")

    files_found = []
    if packet_csv.exists():
        files_found.append("packet_dataset.csv")
    if flow_csv.exists():
        files_found.append("flow_dataset.csv")
    if cicflow_csv.exists():
        files_found.append("cicflow_dataset.csv")

    logger.info(f"Found combined datasets: {', '.join(files_found)}")

    if len(files_found) == 0:
        logger.error("[FAIL] No combined dataset files found. Run combine_datasets.py first.")
        return False

    logger.info("\n[BOOK] Reading combined timeline data...")

    packet_timeline = read_csv_timeline(packet_csv, timestamp_col="auto", label_col=-1, logger=logger) if packet_csv.exists() else {}
    flow_timeline = read_csv_timeline(flow_csv, timestamp_col="auto", label_col=-1, logger=logger) if flow_csv.exists() else {}
    cicflow_timeline = read_csv_timeline(cicflow_csv, timestamp_col="auto", label_col=-1, logger=logger) if cicflow_csv.exists() else {}

    if not packet_timeline and not flow_timeline and not cicflow_timeline:
        logger.error("[FAIL] No timeline data found in any combined dataset file.")
        return False

    analysis = analyze_three_way_coverage(packet_timeline, flow_timeline, cicflow_timeline)

    print_three_way_timeline_table(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger)
    print_detailed_three_way_timing(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger)
    print_three_way_summary_statistics(packet_timeline, flow_timeline, cicflow_timeline, analysis, logger)
    suggest_three_way_improvements(analysis, packet_timeline, flow_timeline, cicflow_timeline, logger)

    return True

def main():
    """Main function to run three-way combined datasets timeline analysis."""
    parser.add_argument('--path', default='../main_output/v3', help='Path to dataset directory (default: ../main_output/v3)')

    args = parser.parse_args()

    dataset_path = Path(args.path)
    if not dataset_path.exists():
        print(f"[FAIL] Error: Dataset directory not found: {dataset_path}")
        return 1

    log_path = dataset_path / "analyze_timeline_v3.log"
    logger = setup_logging(log_path)

    logger.info("[SEARCH] V3 Combined SDN DDoS Datasets Three-Way Timeline Analysis")
    logger.info(f"[DIR] Dataset directory: {dataset_path.absolute()}")

    try:
        if analyze_combined_datasets(dataset_path, logger):
            logger.info(f"\n{'='*80}")
            logger.info("ANALYSIS COMPLETE")
            logger.info(f"{'='*80}")
            logger.info("[DONE] Combined datasets timeline analysis completed successfully!")
            return 0
        else:
            logger.error("[FAIL] Failed to analyze combined datasets")
            return 1
    except Exception as e:
        logger.error(f"Error during analysis: {e}")
        return 1

if __name__ == "__main__":
    exit(main())