"""Remove rows tagged with an 'unknown' label from UKMDDoSDN v1.0 combined datasets.

Usage:
    python3 remove_unknown_labels.py [--version VERSION] [--dry-run]

Arguments:
    --version VERSION    Version directory to process (default: v3)
    --dry-run           Only analyze without making changes
"""
import pandas as pd
import argparse
import logging
import shutil
from pathlib import Path
from datetime import datetime

def setup_logging(log_path=None):
    """Set up logging configuration."""
    handlers = [logging.StreamHandler()]
    if log_path:
        handlers.append(logging.FileHandler(log_path, mode='w'))

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=handlers,
    )
    return logging.getLogger(__name__)


def analyze_dataset_labels(csv_path, dataset_name, logger):
    """Analyze labels in a dataset and return statistics."""
    if not csv_path.exists():
        logger.warning("%s not found: %s", dataset_name, csv_path)
        return None

    try:
        logger.info("Analyzing %s...", dataset_name)
        df = pd.read_csv(csv_path)

        if 'Label_multi' not in df.columns:
            logger.error("Label_multi column not found in %s", dataset_name)
            return None

        label_counts = df['Label_multi'].value_counts()
        total_records = len(df)
        unknown_count = label_counts.get('unknown', 0)
        unknown_percentage = (unknown_count / total_records * 100) if total_records else 0.0

        analysis = {
            'dataset_name': dataset_name,
            'csv_path': csv_path,
            'total_records': total_records,
            'unique_labels': len(label_counts),
            'unknown_count': unknown_count,
            'unknown_percentage': round(unknown_percentage, 2),
            'label_distribution': label_counts.to_dict(),
            'dataframe': df,
        }

        logger.info("%s Analysis:", dataset_name)
        logger.info("  Total records: %s", f"{total_records:,}")
        logger.info("  Unique labels: %s", len(label_counts))
        logger.info("  Unknown records: %s (%0.2f%%)", f"{unknown_count:,}", unknown_percentage)

        if len(label_counts) <= 10:
            logger.info("  Label distribution:")
            for label, count in label_counts.items():
                pct = (count / total_records * 100) if total_records else 0.0
                logger.info("    %s: %s (%0.2f%%)", label, f"{count:,}", pct)

        return analysis

    except Exception as exc:  # pragma: no cover - defensive
        logger.error("Error analyzing %s: %s", dataset_name, exc)
        return None


def remove_unknown_labels(analysis, logger, dry_run=False):
    """Remove rows with 'unknown' label using analysis metadata."""
    if not analysis:
        return False

    df = analysis['dataframe']
    csv_path: Path = analysis['csv_path']
    unknown_count = analysis['unknown_count']

    if unknown_count == 0:
        logger.info("[SKIP] No unknown labels to remove for %s", analysis['dataset_name'])
        return True

    if dry_run:
        logger.info("[DRY RUN] Would remove %s rows from %s", unknown_count, csv_path.name)
        return True

    backup_path = csv_path.with_suffix('.csv.backup_unknown')
    if not backup_path.exists():
        shutil.copy2(csv_path, backup_path)
        logger.info("[BACKUP] Created %s", backup_path.name)

    cleaned_df = df[df['Label_multi'] != 'unknown'].copy()
    cleaned_df.to_csv(csv_path, index=False)
    logger.info("[SAVE] Removed %s rows with 'unknown' label from %s", unknown_count, csv_path.name)
    return True


def analyze_dataset_consistency(analyses, logger):
    """Compute simple consistency metrics across datasets."""
    analyses = [a for a in analyses if a]
    if not analyses:
        return {}, 0.0

    coverage = {a['dataset_name']: a['label_distribution'] for a in analyses}
    label_sets = [set(dist.keys()) for dist in coverage.values()]
    common_labels = set.intersection(*label_sets) if label_sets else set()
    consistency_score = len(common_labels) / max(len(label_sets[0]), 1)

    logger.info("[CONSISTENCY] Common labels across datasets: %s", sorted(common_labels))
    logger.info("[CONSISTENCY] Consistency score: %.2f", consistency_score)
    return coverage, round(consistency_score, 2)


def generate_summary_report(analyses, consistency_score, logger, dry_run=False):
    """Emit a summary of the clean-up operation."""
    logger.info("\n%sSUMMARY REPORT", "DRY RUN " if dry_run else "")
    for analysis in analyses:
        if not analysis:
            continue
        logger.info(
            "- %s: total=%s, unknown_removed=%s",
            analysis['dataset_name'],
            f"{analysis['total_records']:,}",
            f"{analysis['unknown_count']:,}",
        )
    logger.info("Consistency score after clean-up: %.2f", consistency_score)

def main():
    """Main function to remove unknown labels from combined datasets."""
    parser = argparse.ArgumentParser(description="Remove rows labelled as unknown")
    parser.add_argument('--path', default='../main_output/v3', help='Path to dataset directory (default: ../main_output/v3)')
    parser.add_argument('--dry-run', action='store_true', help='Only analyze without making changes')

    args = parser.parse_args()

    dataset_path = Path(args.path)
    if not dataset_path.exists():
        print(f"[FAIL] Error: Dataset directory not found: {dataset_path}")
        return 1

    log_path = dataset_path / "remove_unknown_labels.log"
    logger = setup_logging(log_path)

    operation = "DRY RUN - " if args.dry_run else ""
    logger.info(f"[CLEAN] {operation}Remove Unknown Labels from Combined Datasets")
    logger.info(f"[DIR] Dataset directory: {dataset_path.absolute()}")

    datasets = [
        (dataset_path / "packet_dataset.csv", "Packet Dataset"),
        (dataset_path / "flow_dataset.csv", "Flow Dataset"),
        (dataset_path / "cicflow_dataset.csv", "CICFlow Dataset")
    ]

    analyses = []
    logger.info(f"\n{'='*60}")
    logger.info("ANALYZING DATASETS FOR UNKNOWN LABELS")
    logger.info(f"{'='*60}")

    for csv_path, dataset_name in datasets:
        analysis = analyze_dataset_labels(csv_path, dataset_name, logger)
        analyses.append(analysis)

    unknown_found = any(analysis and analysis['unknown_count'] > 0 for analysis in analyses)

    if not unknown_found:
        logger.info("\n[DONE] No unknown labels found in any dataset!")
        logger.info("All datasets are already clean and ready for ML training.")
        return 0

    logger.info(f"\n{'='*60}")
    logger.info(f"{operation.upper()}REMOVING UNKNOWN LABELS")
    logger.info(f"{'='*60}")

    success_count = 0
    for analysis in analyses:
        if analysis:
            if remove_unknown_labels(analysis, logger, dry_run=args.dry_run):
                success_count += 1

    if not args.dry_run:
        post_removal_analyses = []
        for csv_path, dataset_name in datasets:
            analysis = analyze_dataset_labels(csv_path, dataset_name, logger)
            post_removal_analyses.append(analysis)

        label_coverage, consistency_score = analyze_dataset_consistency(post_removal_analyses, logger)
    else:
        simulated_analyses = []
        for analysis in analyses:
            if analysis and analysis['dataframe'] is not None:
                filtered_df = analysis['dataframe'][analysis['dataframe']['Label_multi'] != 'unknown']
                simulated_analysis = analysis.copy()
                simulated_analysis['dataframe'] = filtered_df
                simulated_analyses.append(simulated_analysis)

        label_coverage, consistency_score = analyze_dataset_consistency(simulated_analyses, logger)

    generate_summary_report(analyses, consistency_score, logger, dry_run=args.dry_run)

    if success_count == len([a for a in analyses if a is not None]):
        logger.info(f"\n[DONE] {operation}Operation completed successfully!")
        return 0
    else:
        logger.error(f"\n[FAIL] Some datasets failed to process")
        return 1

if __name__ == "__main__":
    exit(main())
