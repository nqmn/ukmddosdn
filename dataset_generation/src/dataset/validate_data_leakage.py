"""Decision-tree analysis for detecting data leakage in UKMDDoSDN v1.0 combined datasets.

Usage:
    python3 validate_data_leakage.py [path]

Arguments:
    path: Path to v3 directory containing combined datasets (default: ../main_output/v3/)
"""
import pandas as pd
import numpy as np
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score, confusion_matrix
from sklearn.tree import export_text
import warnings
import os
import sys
import argparse
import glob
from pathlib import Path
from datetime import datetime
import json
warnings.filterwarnings('ignore')

def load_and_preprocess_data(filepath):
    """Load dataset and remove network identifiers that could cause leakage"""
    df = pd.read_csv(filepath)
    print(f"Original dataset shape: {df.shape}")

    columns_to_drop = [
        'timestamp',
        'ip_src', 'ip_dst',
        'src_port', 'dst_port', 'udp_sport', 'udp_dport',
        'tcp_seq', 'tcp_ack',
        'icmp_id', 'icmp_seq',
        'ip_id',
    ]


    existing_cols_to_drop = [col for col in columns_to_drop if col in df.columns]
    print(f"Dropping network identifier columns: {existing_cols_to_drop}")

    df_clean = df.drop(columns=existing_cols_to_drop)
    print(f"Dataset shape after dropping network identifiers: {df_clean.shape}")

    return df_clean

def encode_categorical_features(df):
    """Encode categorical features to numerical values"""

    categorical_cols = df_encoded.select_dtypes(include=['object']).columns.tolist()

    target_cols = ['Label_multi', 'Label_binary']
    categorical_cols = [col for col in categorical_cols if col not in target_cols]

    print(f"Encoding categorical columns: {categorical_cols}")

    for col in categorical_cols:
        if col in df_encoded.columns:
            le = LabelEncoder()
            df_encoded[col] = le.fit_transform(df_encoded[col].astype(str))

    return df_encoded

def get_drop_reason(feature_name, importance):
    """Get specific reason why a feature should be dropped"""
    if feature_name == 'ip_proto':
        return "Direct protocol identifier (ICMP=1, TCP=6, UDP=17)"
    elif feature_name == 'tcp_window':
        return "Attack tool signature - different tools create distinct window patterns"
    elif feature_name == 'icmp_code':
        return "ICMP-specific field - creates protocol-based separation"
    elif feature_name == 'icmp_type':
        return "CRITICAL: Perfect attack discriminator (Echo=8, Unreachable=3, Reply=0)"
    elif feature_name == 'tcp_flags':
        return "CRITICAL: Protocol-specific flags create perfect separation"
    elif feature_name == 'transport_protocol':
        return "Direct protocol encoding (TCP/UDP/ICMP) - explicit attack type"
    elif feature_name == 'eth_type':
        return "Ethernet type - may correlate with attack protocols"
    elif feature_name == 'udp_len':
        return "UDP-specific field - only exists for UDP packets"
    elif feature_name == 'udp_checksum':
        return "UDP-specific field - attack tools create characteristic checksums"
    elif feature_name == 'tcp_options_len':
        return "TCP-specific field - varies by attack tool configuration"
    elif feature_name == 'tcp_urgent':
        return "TCP-specific field - rarely used, creates perfect separation"
    elif feature_name == 'ip_version':
        return "Constant value (IPv4=4) - no discriminative power"
    elif feature_name == 'ip_frag_offset':
        return "Constant value (0) for unfragmented packets - no discriminative power"
    elif feature_name == 'ip_len':
        return "Packet size - attack payloads create characteristic size patterns"
    elif feature_name == 'packet_length':
        return "Total packet size - highly correlated with attack type payloads"
    elif feature_name == 'ip_flags':
        return "IP fragmentation flags - attack patterns create distinct distributions"
    elif feature_name == 'ip_tos':
        return "Type of Service - attack tools set specific QoS values"
    elif feature_name == 'ip_ttl':
        return "Time to Live - varies by attack tool and source routing"

    elif importance > 0.5:
        return "Extremely high importance - dominates classification decisions"
    elif importance > 0.2:
        return "High importance - major contributor to attack identification"
    elif importance > 0.05:
        return "Medium importance - moderate contributor to classification"
    else:
        return "Low importance - minimal leakage risk, behavioral pattern"

def analyze_feature_distributions(df, target_col, log_file):
    """Analyze feature distributions by target class for leakage detection"""
    print(f"FEATURE DISTRIBUTION ANALYSIS FOR {target_col}")
    print(f"{'='*80}")

    log_file.write(f"\n{'='*80}\n")
    log_file.write(f"FEATURE DISTRIBUTION ANALYSIS FOR {target_col}\n")
    log_file.write(f"{'='*80}\n")

    X = df.drop(columns=['Label_multi', 'Label_binary'])
    y = df[target_col]

    distribution_analysis = {}

    for feature in X.columns:
        if X[feature].dtype in ['int64', 'float64']:
            stats_by_class = df.groupby(target_col)[feature].agg(['mean', 'std', 'min', 'max'])

            print(f"\nFeature: {feature}")
            print(stats_by_class.round(6))

            log_file.write(f"\nFeature: {feature}\n")
            log_file.write(stats_by_class.round(6).to_string())
            log_file.write("\n")

            unique_vals_per_class = df.groupby(target_col)[feature].nunique()
            if len(unique_vals_per_class) > 1:
                max_unique = unique_vals_per_class.max()
                min_unique = unique_vals_per_class.min()
                if max_unique == 1 and min_unique == 1:
                    print(f"[WARN]  WARNING: {feature} may have perfect class separation")
                    log_file.write(f"[WARN]  WARNING: {feature} may have perfect class separation\n")

            distribution_analysis[feature] = stats_by_class.to_dict()

    return distribution_analysis

def test_classification(df, target_col, output_dir):
    """Test classification performance for given target column with detailed logging"""
    print(f"TESTING CLASSIFICATION FOR: {target_col}")
    print(f"{'='*80}")

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_filename = os.path.join(output_dir, f"data_leakage_analysis_{target_col}_{timestamp}.log")

    with open(log_filename, 'w') as log_file:
        log_file.write(f"Data Leakage Analysis Report\n")
        log_file.write(f"Target: {target_col}\n")
        log_file.write(f"Timestamp: {datetime.now()}\n")
        log_file.write(f"{'='*80}\n\n")

        if target_col not in df.columns:
            print(f"Target column '{target_col}' not found in dataset")
            log_file.write(f"ERROR: Target column '{target_col}' not found in dataset\n")
            return None, None

        X = df.drop(columns=['Label_multi', 'Label_binary'])
        y = df[target_col]

        print(f"Features shape: {X.shape}")
        print(f"Target distribution:")
        target_dist = y.value_counts().sort_index()
        print(target_dist)

        log_file.write(f"Features shape: {X.shape}\n")
        log_file.write(f"Feature columns: {list(X.columns)}\n")
        log_file.write(f"Target distribution:\n{target_dist}\n\n")

        distribution_analysis = analyze_feature_distributions(df, target_col, log_file)

        X = X.fillna(0)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )

        print(f"Training set: {X_train.shape[0]} samples")
        print(f"Test set: {X_test.shape[0]} samples")

        log_file.write(f"Training set: {X_train.shape[0]} samples\n")
        log_file.write(f"Test set: {X_test.shape[0]} samples\n\n")

        print("\nTraining Decision Tree classifier...")
        dt = DecisionTreeClassifier(
            random_state=42,
            max_depth=10,
            min_samples_split=5,
            min_samples_leaf=2
        )

        dt.fit(X_train, y_train)

        y_pred = dt.predict(X_test)

        accuracy = accuracy_score(y_test, y_pred)
        print(f"\nAccuracy: {accuracy:.6f}")
        log_file.write(f"Accuracy: {accuracy:.6f}\n\n")

        print(f"\nClassification Report for {target_col}:")
        print("=" * 80)
        report = classification_report(
            y_test, y_pred, 
            digits=6,
            zero_division=0
        )
        print(report)
        log_file.write(f"Classification Report for {target_col}:\n")
        log_file.write("=" * 80 + "\n")
        log_file.write(report)
        log_file.write("\n")

        cm = confusion_matrix(y_test, y_pred)
        print(f"\nConfusion Matrix:")
        print(cm)
        log_file.write(f"\nConfusion Matrix:\n{cm}\n\n")

        feature_importance = pd.DataFrame({
            'feature': X.columns,
            'importance': dt.feature_importances_
        }).sort_values('importance', ascending=False)

        print(f"\n{'='*80}")
        print(f"COMPLETE FEATURE IMPORTANCE ANALYSIS FOR {target_col}")
        print(f"{'='*80}")

        log_file.write(f"{'='*80}\n")
        log_file.write(f"COMPLETE FEATURE IMPORTANCE ANALYSIS FOR {target_col}\n")
        log_file.write(f"{'='*80}\n")

        print(f"{'Rank':<4} {'Feature':<25} {'Importance':<12} {'Percentage':<10} {'Risk Level'}")
        print("-" * 70)

        log_file.write(f"{'Rank':<4} {'Feature':<25} {'Importance':<12} {'Percentage':<10} {'Risk Level'}\n")
        log_file.write("-" * 70 + "\n")

        for idx, (_, row) in enumerate(feature_importance.iterrows(), 1):
            importance = row['importance']
            percentage = importance * 100

            if importance > 0.8:
                risk = "[ALERT] CRITICAL"
            elif importance > 0.5:
                risk = "[WARN]  HIGH"
            elif importance > 0.2:
                risk = "[POWER] MEDIUM"
            elif importance > 0.05:
                risk = "[STATS] LOW"
            else:
                risk = "[OK] MINIMAL"

            print(f"{idx:<4} {row['feature']:<25} {importance:<12.6f} {percentage:<10.2f}% {risk}")
            log_file.write(f"{idx:<4} {row['feature']:<25} {importance:<12.6f} {percentage:<10.2f}% {risk}\n")

        tree_rules = export_text(dt, feature_names=list(X.columns), max_depth=3)
        print(f"\nDecision Tree Rules (Max Depth 3 for readability):")
        print("=" * 60)
        print(tree_rules[:2000])

        log_file.write(f"\nDecision Tree Rules (Max Depth 3):\n")
        log_file.write("=" * 60 + "\n")
        log_file.write(tree_rules)
        log_file.write("\n")

        print(f"\n{'='*80}")
        print(f"COMPREHENSIVE DATA LEAKAGE ASSESSMENT FOR {target_col}")
        print(f"{'='*80}")

        log_file.write(f"\n{'='*80}\n")
        log_file.write(f"COMPREHENSIVE DATA LEAKAGE ASSESSMENT FOR {target_col}\n")
        log_file.write(f"{'='*80}\n")

        leakage_indicators = []

        if accuracy > 0.99:
            leakage_indicators.append("CRITICAL: Accuracy > 99% - Near perfect classification")
        elif accuracy > 0.95:
            leakage_indicators.append("HIGH: Accuracy > 95% - Suspiciously high performance")
        elif accuracy > 0.90:
            leakage_indicators.append("MEDIUM: Accuracy > 90% - May indicate some leakage")
        else:
            leakage_indicators.append("LOW: Accuracy < 90% - Acceptable performance")

        top_3_importance = feature_importance.head(3)['importance'].sum()
        if top_3_importance > 0.9:
            leakage_indicators.append("CRITICAL: Top 3 features account for >90% of importance")
        elif top_3_importance > 0.8:
            leakage_indicators.append("HIGH: Top 3 features account for >80% of importance")

        max_importance = feature_importance['importance'].max()
        if max_importance > 0.8:
            top_feature = feature_importance.iloc[0]['feature']
            leakage_indicators.append(f"CRITICAL: Single feature '{top_feature}' dominates with {max_importance:.6f} importance")
        elif max_importance > 0.5:
            top_feature = feature_importance.iloc[0]['feature']
            leakage_indicators.append(f"HIGH: Feature '{top_feature}' has high importance: {max_importance:.6f}")

        zero_importance_count = (feature_importance['importance'] == 0).sum()
        if zero_importance_count > len(feature_importance) * 0.7:
            leakage_indicators.append(f"MEDIUM: {zero_importance_count} features have zero importance (may indicate redundancy)")

        for indicator in leakage_indicators:
            print(f"[STATS] {indicator}")
            log_file.write(f"[STATS] {indicator}\n")

        critical_count = sum(1 for indicator in leakage_indicators if "CRITICAL" in indicator)
        high_count = sum(1 for indicator in leakage_indicators if "HIGH" in indicator)

        if critical_count > 0:
            overall_risk = "[ALERT] CRITICAL DATA LEAKAGE DETECTED"
        elif high_count > 0:
            overall_risk = "[WARN]  HIGH RISK OF DATA LEAKAGE"
        elif accuracy > 0.85:
            overall_risk = "[POWER] MEDIUM RISK - REQUIRES INVESTIGATION"
        else:
            overall_risk = "[OK] LOW RISK - DATASET APPEARS CLEAN"

        print(f"\n[TARGET] OVERALL ASSESSMENT: {overall_risk}")
        log_file.write(f"\n[TARGET] OVERALL ASSESSMENT: {overall_risk}\n")

        print(f"\n{'='*80}")
        print(f"FEATURE DROP RECOMMENDATIONS FOR {target_col}")
        print(f"{'='*80}")

        log_file.write(f"\n{'='*80}\n")
        log_file.write(f"FEATURE DROP RECOMMENDATIONS FOR {target_col}\n")
        log_file.write(f"{'='*80}\n")

        high_risk_features = []
        medium_risk_features = []
        protocol_specific_features = []
        safe_features = []

        for idx, (_, row) in enumerate(feature_importance.iterrows()):
            feature_name = row['feature']
            importance = row['importance']

            if importance > 0.2 or feature_name in ['ip_proto', 'tcp_window', 'icmp_code', 'icmp_type', 'tcp_flags', 'transport_protocol', 'udp_len', 'udp_checksum']:
                high_risk_features.append((feature_name, importance))
            elif feature_name in ['tcp_urgent', 'tcp_options_len', 'ip_version', 'ip_frag_offset', 'eth_type']:
                protocol_specific_features.append((feature_name, importance))
            elif importance > 0.05:
                medium_risk_features.append((feature_name, importance))
            else:
                safe_features.append((feature_name, importance))

        print(f"\n[ALERT] HIGH PRIORITY - MUST DROP ({len(high_risk_features)} features):")
        log_file.write(f"\n[ALERT] HIGH PRIORITY - MUST DROP ({len(high_risk_features)} features):\n")
        for feature, importance in high_risk_features:
            reason = get_drop_reason(feature, importance)
            print(f"   [FAIL] {feature:<20} (importance: {importance:.4f}) - {reason}")
            log_file.write(f"   [FAIL] {feature:<20} (importance: {importance:.4f}) - {reason}\n")

        print(f"\n[WARN]  MEDIUM PRIORITY - CONSIDER DROPPING ({len(medium_risk_features)} features):")
        log_file.write(f"\n[WARN]  MEDIUM PRIORITY - CONSIDER DROPPING ({len(medium_risk_features)} features):\n")
        for feature, importance in medium_risk_features:
            reason = get_drop_reason(feature, importance)
            print(f"   [POWER] {feature:<20} (importance: {importance:.4f}) - {reason}")
            log_file.write(f"   [POWER] {feature:<20} (importance: {importance:.4f}) - {reason}\n")

        print(f"\n[TOOLS] PROTOCOL-SPECIFIC - DROP FOR GENERALIZATION ({len(protocol_specific_features)} features):")
        log_file.write(f"\n[TOOLS] PROTOCOL-SPECIFIC - DROP FOR GENERALIZATION ({len(protocol_specific_features)} features):\n")
        for feature, importance in protocol_specific_features:
            reason = get_drop_reason(feature, importance)
            print(f"   [NOTES] {feature:<20} (importance: {importance:.4f}) - {reason}")
            log_file.write(f"   [NOTES] {feature:<20} (importance: {importance:.4f}) - {reason}\n")

        print(f"\n[OK] SAFE TO KEEP ({len(safe_features)} features):")
        log_file.write(f"\n[OK] SAFE TO KEEP ({len(safe_features)} features):\n")
        for feature, importance in safe_features:
            reason = get_drop_reason(feature, importance)
            print(f"   [OK] {feature:<20} (importance: {importance:.4f}) - {reason}")
            log_file.write(f"   [OK] {feature:<20} (importance: {importance:.4f}) - {reason}\n")

        all_drop_features = [f[0] for f in high_risk_features + medium_risk_features + protocol_specific_features]

        print(f"\n{'='*80}")
        print(f"PYTHON CODE FOR FEATURE DROPPING")
        print(f"{'='*80}")

        log_file.write(f"\n{'='*80}\n")
        log_file.write(f"PYTHON CODE FOR FEATURE DROPPING\n")
        log_file.write(f"{'='*80}\n")

        drop_code = f"""
features_to_drop = {all_drop_features}

df_clean = df.drop(columns=features_to_drop, errors='ignore')
"""
        print(drop_code)
        log_file.write(drop_code)
        log_file.write("\n")

        fi_json_path = os.path.join(output_dir, f"feature_importance_{target_col}_{timestamp}.json")
        feature_importance_dict = {
            'target': target_col,
            'timestamp': datetime.now().isoformat(),
            'accuracy': float(accuracy),
            'feature_importance': feature_importance.to_dict('records'),
            'leakage_indicators': leakage_indicators,
            'overall_risk': overall_risk,
            'distribution_analysis': distribution_analysis
        }

        with open(fi_json_path, 'w') as json_file:
            json.dump(feature_importance_dict, json_file, indent=2)

        print(f"\n[DIR] Detailed analysis saved to: {log_filename}")
        print(f"[DIR] Feature importance data saved to: {fi_json_path}")

        return accuracy, feature_importance

def find_dataset_files(base_path):
    """Find combined dataset files in v3 directory"""
    dataset_files = []

    combined_datasets = [
        'flow_dataset.csv',
        'packet_dataset.csv', 
        'cicflow_dataset.csv'
    ]

    for dataset_name in combined_datasets:
        dataset_path = base_path / dataset_name
        if dataset_path.exists():
            dataset_files.append(dataset_path)

    if not dataset_files:
        for csv_file in base_path.rglob("packet_features_30.csv"):
            dataset_files.append(csv_file)

        for csv_file in base_path.rglob("packet_features.csv"):
            if csv_file not in dataset_files:
                dataset_files.append(csv_file)

    return sorted(dataset_files)

def analyze_single_dataset(filepath, output_dir):
    """Analyze a single dataset file"""
    print(f"ANALYZING: {filepath}")
    print(f"{'='*80}")

    try:
        df = load_and_preprocess_data(str(filepath))
        df_encoded = encode_categorical_features(df)

        print(f"\nDataset info:")
        print(f"Shape: {df_encoded.shape}")
        print(f"Features: {df_encoded.columns.tolist()}")

        results = {}

        if 'Label_binary' in df_encoded.columns:
            acc_binary, fi_binary = test_classification(df_encoded, 'Label_binary', output_dir)
            results['Label_binary'] = acc_binary

        if 'Label_multi' in df_encoded.columns:
            acc_multi, fi_multi = test_classification(df_encoded, 'Label_multi', output_dir)
            results['Label_multi'] = acc_multi

        return results

    except Exception as e:
        print(f"[FAIL] Error processing {filepath}: {e}")
        return {}

def main():
    """Main function to run data leakage validation"""
    parser.add_argument('--path', 
                       default='../main_output/v3/',
                       help='Path to v3 directory containing combined datasets (default: ../main_output/v3/)')

    args = parser.parse_args()

    print("[SEARCH] Data Leakage Validation for UKMDDoSDN v1.0 Combined Datasets")
    print("=" * 70)
    print(f"[DIR] Analyzing combined datasets in: {args.path}")

    dataset_files = find_dataset_files(args.path)

    if not dataset_files:
        print(f"[FAIL] No dataset files found in {args.path}")
        print("   Looking for: flow_dataset.csv, packet_dataset.csv, cicflow_dataset.csv")
        print("   Fallback: packet_features_30.csv or packet_features.csv in subdirectories")
        return

    print(f"[STATS] Found {len(dataset_files)} dataset files:")
    for i, file_path in enumerate(dataset_files, 1):
        print(f"   {i}. {file_path.parent.name}/{file_path.name}")

    output_dir = Path(args.path)
    all_results = {}

    for i, filepath in enumerate(dataset_files, 1):
        dataset_name = f"{filepath.parent.name}/{filepath.name}"
        print(f"\n[SEARCH] [{i}/{len(dataset_files)}] Processing: {dataset_name}")

        results = analyze_single_dataset(filepath, output_dir)
        if results:
            all_results[dataset_name] = results

    print(f"\n{'='*80}")
    print("OVERALL DATA LEAKAGE ASSESSMENT SUMMARY")
    print(f"{'='*80}")

    if not all_results:
        print("[FAIL] No datasets were successfully processed")
        return

    high_risk_datasets = []
    medium_risk_datasets = []
    low_risk_datasets = []

    for dataset_name, results in all_results.items():
        max_accuracy = max(results.values()) if results else 0

        if max_accuracy > 0.95:
            high_risk_datasets.append((dataset_name, max_accuracy))
        elif max_accuracy > 0.90:
            medium_risk_datasets.append((dataset_name, max_accuracy))
        else:
            low_risk_datasets.append((dataset_name, max_accuracy))

    print(f"[STATS] Analysis Results:")
    print(f"   [ALERT] HIGH Risk (>95% accuracy): {len(high_risk_datasets)} datasets")
    print(f"   [WARN]  MEDIUM Risk (90-95% accuracy): {len(medium_risk_datasets)} datasets")
    print(f"   [OK] LOW Risk (<90% accuracy): {len(low_risk_datasets)} datasets")

    print(f"\n[NOTES] Detailed Results:")
    for dataset_name, results in all_results.items():
        print(f"\n[DIR] {dataset_name}:")
        for target, accuracy in results.items():
            risk_level = "[ALERT] HIGH" if accuracy > 0.95 else "[WARN]  MEDIUM" if accuracy > 0.90 else "[OK] LOW"
            print(f"   {target:<15}: {accuracy:.6f} - {risk_level}")

    summary_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    summary_filename = output_dir / f"multi_dataset_leakage_analysis_{summary_timestamp}.md"

    with open(summary_filename, 'w') as summary_file:
        summary_file.write(f"# Combined Dataset Leakage Analysis - UKMDDoSDN v1.0\n\n")
        summary_file.write(f"**Analysis Date:** {datetime.now()}\n")
        summary_file.write(f"**Base Directory:** {args.path}\n")
        summary_file.write(f"**Combined Datasets Analyzed:** {len(all_results)}\n")
        summary_file.write(f"**Dataset Types:** flow_dataset.csv, packet_dataset.csv, cicflow_dataset.csv\n\n")

        summary_file.write(f"## Overall Risk Assessment\n\n")
        summary_file.write(f"- **[ALERT] HIGH Risk**: {len(high_risk_datasets)} datasets (>95% accuracy)\n")
        summary_file.write(f"- **[WARN]  MEDIUM Risk**: {len(medium_risk_datasets)} datasets (90-95% accuracy)\n")
        summary_file.write(f"- **[OK] LOW Risk**: {len(low_risk_datasets)} datasets (<90% accuracy)\n\n")

        summary_file.write(f"## Detailed Results by Dataset\n\n")
        for dataset_name, results in all_results.items():
            summary_file.write(f"### {dataset_name}\n")
            for target, accuracy in results.items():
                risk_level = "HIGH" if accuracy > 0.95 else "MEDIUM" if accuracy > 0.90 else "LOW"
                summary_file.write(f"- **{target}**: {accuracy:.6f} ({risk_level} risk)\n")
            summary_file.write(f"\n")

        summary_file.write(f"## Key Recommendations\n\n")
        summary_file.write(f"1. **Immediate Action**: Drop protocol identifiers (icmp_type, tcp_flags, transport_protocol)\n")
        summary_file.write(f"2. **Review Features**: Analyze tcp_window and packet_length patterns\n")
        summary_file.write(f"3. **Protocol-Agnostic**: Implement behavioral feature engineering\n")
        summary_file.write(f"4. **Target Accuracy**: Aim for 60-75% for realistic behavioral detection\n")

    print(f"\n[DIR] Multi-dataset summary saved to: {summary_filename}")

    if high_risk_datasets:
        print(f"\n[ALERT] CRITICAL: {len(high_risk_datasets)} datasets show severe data leakage")
        print(f"   Immediate action required: Review protocol-level features")
    elif medium_risk_datasets:
        print(f"\n[WARN]  WARNING: {len(medium_risk_datasets)} datasets show potential leakage")
        print(f"   Recommendation: Investigate feature engineering")
    else:
        print(f"\n[OK] GOOD: All datasets show acceptable leakage levels")
        print(f"   Recommendation: Proceed with current feature set")

if __name__ == "__main__":
    main()