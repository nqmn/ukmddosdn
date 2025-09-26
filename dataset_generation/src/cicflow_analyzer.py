#!/usr/bin/env python3
"""
CICFlow Analyzer - Combined Feature Extraction and Validation Tool

This comprehensive script combines:
1. PCAP to CICFlow feature extraction using CICFlowMeter
2. Dataset validation and quality analysis
3. Comprehensive reporting and visualization

Designed for defensive security research and DDoS detection in SDN environments.
"""

import os
import sys
import subprocess
import pandas as pd
import numpy as np
import argparse
from pathlib import Path
import logging
from collections import Counter
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CICFlowAnalyzer:
    def __init__(self, pcap_dir=None, output_dir=None):
        self.pcap_dir = Path(pcap_dir).resolve() if pcap_dir else None
        self.output_dir = Path(output_dir).resolve() if output_dir else Path('cicflow_analysis').resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Label mappings from the label files
        self.multi_labels = {
            'normal': 'normal',
            'syn_flood': 'syn_flood',
            'udp_flood': 'udp_flood',
            'icmp_flood': 'icmp_flood',
            'ad_syn': 'ad_syn',
            'ad_udp': 'ad_udp',
            'ad_slow': 'ad_slow'
        }
        
        self.binary_labels = {
            'normal': 0,
            'syn_flood': 1,
            'udp_flood': 1,
            'icmp_flood': 1,
            'ad_syn': 1,
            'ad_udp': 1,
            'ad_slow': 1
        }
        
        # PCAP file to attack type mapping
        self.pcap_attack_mapping = {
            'normal.pcap': 'normal',
            'syn_flood.pcap': 'syn_flood',
            'udp_flood.pcap': 'udp_flood',
            'icmp_flood.pcap': 'icmp_flood',
            'ad_syn.pcap': 'ad_syn',
            'ad_udp.pcap': 'ad_udp',
            'ad_slow.pcap': 'ad_slow'
        }
        
        # Analysis results storage
        self.analysis_results = {}
        self.extracted_df = None

    # =============================================================================
    # FEATURE EXTRACTION METHODS
    # =============================================================================
    
    def check_cicflowmeter(self):
        """Check if CICFlowMeter is installed and accessible"""
        try:
            result = subprocess.run(['cicflowmeter', '--help'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                logger.info("CICFlowMeter is available")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.error("CICFlowMeter not found. Please install it:")
        logger.error("pip install cicflowmeter")
        logger.error("or")
        logger.error("git clone https://github.com/datthinh1801/cicflowmeter.git")
        logger.error("cd cicflowmeter && pip install .")
        return False

    def extract_features_from_pcap(self, pcap_file):
        """Extract features from a single PCAP file using CICFlowMeter"""
        if isinstance(pcap_file, str):
            pcap_file = Path(pcap_file)
        
        # Handle both absolute and relative paths correctly
        if pcap_file.is_absolute():
            pcap_path = pcap_file
        else:
            pcap_path = self.pcap_dir / pcap_file.name
        
        temp_output = self.output_dir / f"temp_{pcap_file.stem}_flows.csv"
        
        if not pcap_path.exists():
            logger.warning(f"PCAP file not found: {pcap_path}")
            return None
        
        logger.info(f"Processing {pcap_file}...")
        
        try:
            # Run CICFlowMeter
            cmd = [
                'cicflowmeter',
                '-f', str(pcap_path),
                '-c', str(temp_output)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode != 0:
                logger.error(f"CICFlowMeter failed for {pcap_file}: {result.stderr}")
                logger.debug(f"CICFlowMeter stdout: {result.stdout}")
                return None
            
            # Check if output file was created
            if not temp_output.exists():
                logger.error(f"No output file generated for {pcap_file}")
                return None
            
            # Read the generated CSV
            try:
                df = pd.read_csv(temp_output)
                if len(df) == 0:
                    logger.warning(f"No flows found in output for {pcap_file}")
                    temp_output.unlink()
                    return None
                logger.info(f"Extracted {len(df)} flows from {pcap_file}")
            except pd.errors.EmptyDataError:
                logger.warning(f"CICFlowMeter generated empty output for {pcap_file}")
                temp_output.unlink()
                return None
            except Exception as e:
                logger.error(f"Error reading CICFlowMeter output for {pcap_file}: {e}")
                if temp_output.exists():
                    temp_output.unlink()
                return None
            
            # Clean up temporary file
            temp_output.unlink()
            
            return df
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout processing {pcap_file}")
            return None
        except Exception as e:
            logger.error(f"Error processing {pcap_file}: {e}")
            return None

    def add_labels(self, df, attack_type):
        """Add multi-class and binary labels to the dataframe"""
        df = df.copy()
        df['Label_multi'] = self.multi_labels[attack_type]
        df['Label_binary'] = self.binary_labels[attack_type]
        return df

    def extract_all_features(self):
        """Process all PCAP files and combine into labeled datasets"""
        if not self.pcap_dir:
            logger.error("PCAP directory not specified")
            return False
            
        if not self.pcap_dir.exists():
            logger.error(f"PCAP directory not found: {self.pcap_dir}")
            return False
        
        # Check CICFlowMeter availability
        if not self.check_cicflowmeter():
            return False
        
        all_flows = []
        
        # Find PCAP files in the directory
        pcap_files = list(self.pcap_dir.glob("*.pcap"))
        
        if not pcap_files:
            logger.error(f"No PCAP files found in {self.pcap_dir}")
            return False
        
        logger.info(f"Found {len(pcap_files)} PCAP files")
        
        for pcap_file in pcap_files:
            # Determine attack type from filename
            attack_type = self.pcap_attack_mapping.get(pcap_file.name)
            
            if not attack_type:
                logger.warning(f"Unknown attack type for {pcap_file.name}, skipping...")
                continue
            
            # Extract features
            df = self.extract_features_from_pcap(pcap_file)
            
            if df is not None and len(df) > 0:
                # Add labels
                df_labeled = self.add_labels(df, attack_type)
                all_flows.append(df_labeled)
                logger.info(f"Added {len(df_labeled)} labeled flows for {attack_type}")
            else:
                logger.warning(f"No flows extracted from {pcap_file.name}")
        
        if not all_flows:
            logger.error("No flows were extracted from any PCAP files")
            return False
        
        # Combine all flows
        self.extracted_df = pd.concat(all_flows, ignore_index=True)
        
        # Save combined dataset
        output_file = self.output_dir / "cicflow_features_all.csv"
        self.extracted_df.to_csv(output_file, index=False)
        logger.info(f"Saved combined dataset with {len(self.extracted_df)} flows to {output_file}")
        
        return True

    # =============================================================================
    # VALIDATION METHODS
    # =============================================================================
    
    def load_dataset(self, csv_path):
        """Load CSV dataset for validation"""
        logger.info(f"Loading dataset from: {csv_path}")
        
        if not Path(csv_path).exists():
            logger.error(f"File not found: {csv_path}")
            return None
        
        try:
            df = pd.read_csv(csv_path)
            logger.info(f"Dataset loaded successfully: {len(df)} rows, {len(df.columns)} columns")
            return df
        except Exception as e:
            logger.error(f"Error loading CSV: {e}")
            return None

    def analyze_attack_distribution(self, df):
        """Analyze attack type distribution"""
        print("\n" + "="*60)
        print("ATTACK TYPE DISTRIBUTION ANALYSIS")
        print("="*60)
        
        if 'Attack_Type' not in df.columns:
            print("[FAIL] ERROR: 'Attack_Type' column not found")
            return None
        
        attack_counts = df['Attack_Type'].value_counts()
        print(f"\nTotal flows: {len(df)}")
        print(f"Unique attack types: {len(attack_counts)}")
        print("\nAttack Type Distribution:")
        
        for attack_type, count in attack_counts.items():
            percentage = (count / len(df)) * 100
            print(f"  {attack_type:<15}: {count:>6} flows ({percentage:>6.2f}%)")
        
        self.analysis_results['attack_distribution'] = attack_counts
        return attack_counts

    def analyze_protocol_correctness(self, df):
        """Analyze protocol field correctness"""
        print("\n" + "="*60)
        print("PROTOCOL CORRECTNESS ANALYSIS")
        print("="*60)
        
        if 'protocol' not in df.columns:
            print("[FAIL] ERROR: 'protocol' column not found")
            return
        
        protocol_counts = df['protocol'].value_counts()
        print(f"\nProtocol Distribution:")
        
        # Expected protocol mappings
        protocol_map = {
            1: "ICMP",
            6: "TCP", 
            17: "UDP",
            2048: "Unknown/Ethernet Type (should be 1/6/17)"
        }
        
        total_flows = len(df)
        protocol_issues = 0
        
        for protocol, count in protocol_counts.items():
            protocol_name = protocol_map.get(protocol, f"Unknown ({protocol})")
            percentage = (count / total_flows) * 100
            status = "[OK]" if protocol in [1, 6, 17] else "[FAIL]"
            if protocol not in [1, 6, 17]:
                protocol_issues += count
            print(f"  {status} Protocol {protocol:<4} ({protocol_name:<35}): {count:>6} flows ({percentage:>6.2f}%)")
        
        # Check for protocol consistency by attack type
        if 'Attack_Type' in df.columns:
            print(f"\nProtocol by Attack Type:")
            protocol_by_attack = df.groupby(['Attack_Type', 'protocol']).size().unstack(fill_value=0)
            print(protocol_by_attack)
        
        self.analysis_results['protocol_issues'] = protocol_issues
        self.analysis_results['protocol_distribution'] = protocol_counts

    def analyze_flow_characteristics(self, df):
        """Analyze flow characteristics by attack type"""
        print("\n" + "="*60)
        print("FLOW CHARACTERISTICS ANALYSIS")
        print("="*60)
        
        required_cols = ['Attack_Type', 'src_port', 'dst_port', 'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts']
        missing_cols = [col for col in required_cols if col not in df.columns]
        
        if missing_cols:
            print(f"[FAIL] ERROR: Missing columns: {missing_cols}")
            return
        
        # Analyze by attack type
        attack_types = df['Attack_Type'].unique()
        flow_characteristics = {}
        
        for attack_type in sorted(attack_types):
            attack_df = df[df['Attack_Type'] == attack_type]
            
            print(f"\n--- {attack_type.upper()} Analysis ---")
            print(f"Flows: {len(attack_df)}")
            
            char_data = {'flow_count': len(attack_df)}
            
            # Port analysis
            if attack_type in ['syn_flood', 'ad_syn']:
                # Should target port 80 (HTTP)
                port_80_flows = len(attack_df[attack_df['dst_port'] == 80])
                port_80_ratio = (port_80_flows/len(attack_df)*100) if len(attack_df) > 0 else 0
                print(f"Port 80 targets: {port_80_flows}/{len(attack_df)} ({port_80_ratio:.1f}%)")
                char_data['port_80_ratio'] = port_80_ratio
                
            elif attack_type in ['udp_flood', 'ad_udp']:
                # Should target port 53 (DNS) or use realistic UDP ports
                port_53_flows = len(attack_df[attack_df['dst_port'] == 53])
                port_53_ratio = (port_53_flows/len(attack_df)*100) if len(attack_df) > 0 else 0
                print(f"Port 53 targets: {port_53_flows}/{len(attack_df)} ({port_53_ratio:.1f}%)")
                char_data['port_53_ratio'] = port_53_ratio
                
            elif attack_type == 'icmp_flood':
                # ICMP should have port -1 or no port
                icmp_ports = attack_df['dst_port'].unique()
                print(f"ICMP ports: {icmp_ports}")
                char_data['icmp_ports'] = icmp_ports
            
            # Source port analysis (should be ephemeral for enhanced attacks)
            src_ports = attack_df['src_port'].dropna()
            if len(src_ports) > 0:
                ephemeral_ports = src_ports[(src_ports >= 32768) & (src_ports <= 65535)]
                ephemeral_ratio = len(ephemeral_ports) / len(src_ports) * 100
                print(f"Ephemeral source ports: {len(ephemeral_ports)}/{len(src_ports)} ({ephemeral_ratio:.1f}%)")
                char_data['ephemeral_ratio'] = ephemeral_ratio
                
            # Flow duration analysis
            durations = attack_df['flow_duration'].dropna()
            if len(durations) > 0:
                duration_mean = durations.mean()
                duration_median = durations.median()
                print(f"Flow duration - Mean: {duration_mean:.3f}s, Median: {duration_median:.3f}s")
                char_data['duration_mean'] = duration_mean
                char_data['duration_median'] = duration_median
                
            # Packet count analysis
            fwd_pkts = attack_df['tot_fwd_pkts'].dropna()
            bwd_pkts = attack_df['tot_bwd_pkts'].dropna()
            if len(fwd_pkts) > 0:
                fwd_mean = fwd_pkts.mean()
                fwd_median = fwd_pkts.median()
                print(f"Forward packets - Mean: {fwd_mean:.1f}, Median: {fwd_median:.1f}")
                char_data['fwd_pkts_mean'] = fwd_mean
                char_data['fwd_pkts_median'] = fwd_median
            if len(bwd_pkts) > 0:
                bwd_mean = bwd_pkts.mean()
                bwd_median = bwd_pkts.median()
                print(f"Backward packets - Mean: {bwd_mean:.1f}, Median: {bwd_median:.1f}")
                char_data['bwd_pkts_mean'] = bwd_mean
                char_data['bwd_pkts_median'] = bwd_median
            
            flow_characteristics[attack_type] = char_data
        
        self.analysis_results['flow_characteristics'] = flow_characteristics

    def analyze_tcp_flags(self, df):
        """Analyze TCP flags for SYN flood attacks"""
        print("\n" + "="*60)
        print("TCP FLAGS ANALYSIS") 
        print("="*60)
        
        tcp_attacks = df[df['Attack_Type'].isin(['syn_flood', 'ad_syn'])].copy()
        
        if len(tcp_attacks) == 0:
            print("No TCP-based attacks found for flag analysis")
            return
        
        flag_cols = ['syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt']
        missing_flag_cols = [col for col in flag_cols if col not in df.columns]
        
        if missing_flag_cols:
            print(f"[FAIL] Missing flag columns: {missing_flag_cols}")
            return
        
        tcp_flag_analysis = {}
        
        for attack_type in ['syn_flood', 'ad_syn']:
            attack_df = tcp_attacks[tcp_attacks['Attack_Type'] == attack_type]
            if len(attack_df) == 0:
                continue
                
            print(f"\n--- {attack_type.upper()} TCP Flags ---")
            flag_data = {}
            
            for flag_col in flag_cols:
                if flag_col in attack_df.columns:
                    flag_counts = attack_df[flag_col].dropna()
                    if len(flag_counts) > 0:
                        flag_name = flag_col.replace('_flag_cnt', '').upper()
                        flag_mean = flag_counts.mean()
                        flag_max = flag_counts.max()
                        print(f"{flag_name} flags - Mean: {flag_mean:.2f}, Max: {flag_max}")
                        flag_data[flag_name] = {'mean': flag_mean, 'max': flag_max}
            
            tcp_flag_analysis[attack_type] = flag_data
        
        self.analysis_results['tcp_flags'] = tcp_flag_analysis

    def analyze_enhanced_features(self, df):
        """Analyze features that indicate enhanced traditional attacks"""
        print("\n" + "="*60)
        print("ENHANCED ATTACK FEATURES ANALYSIS")
        print("="*60)
        
        traditional_attacks = df[df['Attack_Type'].isin(['syn_flood', 'udp_flood', 'icmp_flood'])].copy()
        
        if len(traditional_attacks) == 0:
            print("No traditional attacks found for enhanced feature analysis")
            return
        
        print(f"Traditional attack flows: {len(traditional_attacks)}")
        
        enhanced_analysis = {}
        
        # Analyze timing patterns (should show ~25 pps for enhanced attacks)
        if 'flow_pkts_s' in df.columns:
            for attack_type in ['syn_flood', 'udp_flood', 'icmp_flood']:
                attack_df = traditional_attacks[traditional_attacks['Attack_Type'] == attack_type]
                if len(attack_df) > 0:
                    pkt_rates = attack_df['flow_pkts_s'].dropna()
                    if len(pkt_rates) > 0:
                        mean_rate = pkt_rates.mean()
                        enhancement_indicator = "[OK] Enhanced" if mean_rate < 50 else "[FAIL] Traditional"
                        print(f"{attack_type}: Avg packet rate = {mean_rate:.1f} pps ({enhancement_indicator})")
                        enhanced_analysis[attack_type] = {
                            'packet_rate': mean_rate,
                            'is_enhanced': mean_rate < 50
                        }
        
        # Check for realistic source ports (ephemeral range)
        for attack_type in ['syn_flood', 'udp_flood']:
            attack_df = traditional_attacks[traditional_attacks['Attack_Type'] == attack_type]
            if len(attack_df) > 0 and 'src_port' in attack_df.columns:
                src_ports = attack_df['src_port'].dropna()
                ephemeral_ports = src_ports[(src_ports >= 32768) & (src_ports <= 65535)]
                if len(src_ports) > 0:
                    ephemeral_ratio = len(ephemeral_ports) / len(src_ports) * 100
                    enhancement_indicator = "[OK] Enhanced" if ephemeral_ratio > 80 else "[FAIL] Basic"
                    print(f"{attack_type}: Ephemeral ports = {ephemeral_ratio:.1f}% ({enhancement_indicator})")
                    if attack_type not in enhanced_analysis:
                        enhanced_analysis[attack_type] = {}
                    enhanced_analysis[attack_type]['ephemeral_ratio'] = ephemeral_ratio
                    enhanced_analysis[attack_type]['ephemeral_enhanced'] = ephemeral_ratio > 80
        
        self.analysis_results['enhanced_features'] = enhanced_analysis

    def analyze_labels_consistency(self, df):
        """Analyze label consistency"""
        print("\n" + "="*60)
        print("LABEL CONSISTENCY ANALYSIS")
        print("="*60)
        
        label_cols = ['Label_multi', 'Label_binary', 'Attack_Type']
        missing_cols = [col for col in label_cols if col not in df.columns]
        
        if missing_cols:
            print(f"[FAIL] Missing label columns: {missing_cols}")
            return
        
        # Check Label_binary consistency
        print("Label_binary Consistency:")
        normal_binary = df[df['Attack_Type'] == 'normal']['Label_binary'].unique()
        attack_binary = df[df['Attack_Type'] != 'normal']['Label_binary'].unique()
        
        print(f"Normal traffic Label_binary: {normal_binary}")
        print(f"Attack traffic Label_binary: {attack_binary}")
        
        # Expected: Normal = 0, Attacks = 1
        normal_correct = all(label == 0 for label in normal_binary)
        attack_correct = all(label == 1 for label in attack_binary)
        
        print(f"Normal labeling correct: {'[OK]' if normal_correct else '[FAIL]'}")
        print(f"Attack labeling correct: {'[OK]' if attack_correct else '[FAIL]'}")
        
        # Label_multi analysis
        print(f"\nLabel_multi Distribution:")
        label_multi_map = df.groupby(['Attack_Type', 'Label_multi']).size().unstack(fill_value=0)
        print(label_multi_map)
        
        self.analysis_results['label_consistency'] = {
            'normal_binary_correct': normal_correct,
            'attack_binary_correct': attack_correct,
            'label_multi_map': label_multi_map
        }

    def generate_summary_report(self, df):
        """Generate comprehensive summary report"""
        print("\n" + "="*60)
        print("VALIDATION SUMMARY REPORT")
        print("="*60)
        
        total_flows = len(df)
        attack_counts = self.analysis_results.get('attack_distribution', {})
        
        # Dataset composition
        print(f"\n[STATS] Dataset Composition:")
        print(f"   Total flows: {total_flows}")
        print(f"   Attack types: {len(attack_counts) if attack_counts is not None else 'Unknown'}")
        
        # Protocol validation
        protocol_issues = self.analysis_results.get('protocol_issues', 0)
        print(f"\n[SEARCH] Protocol Validation:")
        protocol_correct_count = total_flows - protocol_issues
        print(f"   Correct protocols (1/6/17): {protocol_correct_count}/{total_flows} ({(protocol_correct_count/total_flows*100):.1f}%)")
        print(f"   Incorrect protocol issues: {protocol_issues}/{total_flows} ({(protocol_issues/total_flows*100):.1f}%)")
        
        # Enhanced attacks validation
        traditional_count = len(df[df['Attack_Type'].isin(['syn_flood', 'udp_flood', 'icmp_flood'])])
        adversarial_count = len(df[df['Attack_Type'].isin(['ad_syn', 'ad_udp', 'ad_slow'])])
        normal_count = len(df[df['Attack_Type'] == 'normal'])
        
        print(f"\n[CHECK] Attack Category Distribution:")
        print(f"   Enhanced Traditional: {traditional_count} flows ({(traditional_count/total_flows*100):.1f}%)")
        print(f"   Adversarial: {adversarial_count} flows ({(adversarial_count/total_flows*100):.1f}%)")
        print(f"   Normal: {normal_count} flows ({(normal_count/total_flows*100):.1f}%)")
        
        # Issues and recommendations
        print(f"\n[WARN] Issues Identified:")
        issues = []
        
        if protocol_issues > 0:
            issues.append("Protocol field contains incorrect values (should be 1=ICMP, 6=TCP, 17=UDP)")
        
        if traditional_count < adversarial_count:
            issues.append("Few enhanced traditional attack flows captured")
        
        # Check for balanced dataset
        if attack_counts is not None and not attack_counts.empty:
            max_count = max(attack_counts.values)
            min_count = min(attack_counts.values)
            if max_count > min_count * 10:  # More than 10x imbalance
                issues.append("Severe class imbalance detected in attack distribution")
        
        if len(issues) == 0:
            print("   [OK] No major issues detected")
        else:
            for i, issue in enumerate(issues, 1):
                print(f"   {i}. {issue}")
        
        print(f"\n[IDEA] Recommendations:")
        recommendations = [
            "Fix protocol encoding in packet capture/flow generation",
            "Increase duration for traditional attacks to capture more flows",
            "Verify enhanced timing features are working correctly",
            "Ensure proper port targeting (80 for SYN, 53 for UDP, -1 for ICMP)",
            "Balance dataset by adjusting scenario durations"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"   {i}. {rec}")
        
        # Save detailed report
        self.save_detailed_report(df)

    def save_detailed_report(self, df):
        """Save detailed analysis report to file"""
        report_file = self.output_dir / f"analysis_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_file, 'w') as f:
            f.write("CICFlow Dataset Analysis Report\n")
            f.write("=" * 50 + "\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write(f"Dataset Overview:\n")
            f.write(f"  Total flows: {len(df)}\n")
            f.write(f"  Total features: {len(df.columns)}\n")
            f.write(f"  Analysis output directory: {self.output_dir}\n\n")
            
            # Attack distribution
            if 'attack_distribution' in self.analysis_results:
                f.write("Attack Distribution:\n")
                for attack, count in self.analysis_results['attack_distribution'].items():
                    percentage = (count / len(df)) * 100
                    f.write(f"  {attack}: {count} flows ({percentage:.2f}%)\n")
                f.write("\n")
            
            # Protocol analysis
            if 'protocol_distribution' in self.analysis_results:
                f.write("Protocol Distribution:\n")
                for protocol, count in self.analysis_results['protocol_distribution'].items():
                    percentage = (count / len(df)) * 100
                    f.write(f"  Protocol {protocol}: {count} flows ({percentage:.2f}%)\n")
                f.write("\n")
            
            # Enhanced features
            if 'enhanced_features' in self.analysis_results:
                f.write("Enhanced Attack Features:\n")
                for attack, features in self.analysis_results['enhanced_features'].items():
                    f.write(f"  {attack}:\n")
                    for feature, value in features.items():
                        f.write(f"    {feature}: {value}\n")
                f.write("\n")
            
            # Flow characteristics
            if 'flow_characteristics' in self.analysis_results:
                f.write("Flow Characteristics by Attack Type:\n")
                for attack, chars in self.analysis_results['flow_characteristics'].items():
                    f.write(f"  {attack}:\n")
                    for char, value in chars.items():
                        f.write(f"    {char}: {value}\n")
                f.write("\n")
            
            f.write("Feature columns:\n")
            for i, col in enumerate(df.columns, 1):
                f.write(f"  {i:2d}. {col}\n")
        
        logger.info(f"Detailed analysis report saved to: {report_file}")

    def create_visualizations(self, df):
        """Create comprehensive visualization plots"""
        logger.info("Generating visualizations...")
        
        # Set up the plotting style
        plt.style.use('seaborn-v0_8')
        
        # Create multiple visualization plots
        fig, axes = plt.subplots(2, 3, figsize=(18, 12))
        fig.suptitle('CICFlow Dataset Analysis Visualizations', fontsize=16, fontweight='bold')
        
        # 1. Attack Type Distribution
        if 'attack_distribution' in self.analysis_results:
            attack_counts = self.analysis_results['attack_distribution']
            ax1 = axes[0, 0]
            attack_counts.plot(kind='bar', ax=ax1, color='skyblue')
            ax1.set_title('Attack Type Distribution')
            ax1.set_xlabel('Attack Type')
            ax1.set_ylabel('Number of Flows')
            ax1.tick_params(axis='x', rotation=45)
        
        # 2. Protocol Distribution
        if 'protocol_distribution' in self.analysis_results:
            protocol_counts = self.analysis_results['protocol_distribution']
            ax2 = axes[0, 1]
            protocol_counts.plot(kind='pie', ax=ax2, autopct='%1.1f%%')
            ax2.set_title('Protocol Distribution')
            ax2.set_ylabel('')
        
        # 3. Binary Label Distribution
        ax3 = axes[0, 2]
        if 'Label_binary' in df.columns:
            binary_counts = df['Label_binary'].value_counts()
            labels = ['Normal', 'Attack']
            colors = ['lightgreen', 'lightcoral']
            binary_counts.plot(kind='pie', ax=ax3, autopct='%1.1f%%', labels=labels, colors=colors)
            ax3.set_title('Binary Classification Distribution')
            ax3.set_ylabel('')
        
        # 4. Flow Duration by Attack Type
        ax4 = axes[1, 0]
        if 'flow_duration' in df.columns:
            attack_types = df['Attack_Type'].unique()
            duration_data = [df[df['Attack_Type'] == attack]['flow_duration'].dropna() for attack in attack_types]
            ax4.boxplot(duration_data, labels=attack_types)
            ax4.set_title('Flow Duration by Attack Type')
            ax4.set_xlabel('Attack Type')
            ax4.set_ylabel('Flow Duration (seconds)')
            ax4.tick_params(axis='x', rotation=45)
        
        # 5. Packet Rate Analysis
        ax5 = axes[1, 1]
        if 'flow_pkts_s' in df.columns:
            traditional_attacks = df[df['Attack_Type'].isin(['syn_flood', 'udp_flood', 'icmp_flood'])]
            if len(traditional_attacks) > 0:
                pkt_rates = traditional_attacks.groupby('Attack_Type')['flow_pkts_s'].mean()
                pkt_rates.plot(kind='bar', ax=ax5, color='orange')
                ax5.set_title('Average Packet Rate by Traditional Attack')
                ax5.set_xlabel('Attack Type')
                ax5.set_ylabel('Packets per Second')
                ax5.tick_params(axis='x', rotation=45)
                ax5.axhline(y=50, color='red', linestyle='--', label='Enhanced Threshold (50 pps)')
                ax5.legend()
        
        # 6. Port Distribution for TCP Attacks
        ax6 = axes[1, 2]
        tcp_attacks = df[df['Attack_Type'].isin(['syn_flood', 'ad_syn'])]
        if len(tcp_attacks) > 0 and 'dst_port' in tcp_attacks.columns:
            port_counts = tcp_attacks['dst_port'].value_counts().head(10)
            port_counts.plot(kind='bar', ax=ax6, color='purple')
            ax6.set_title('Top 10 Destination Ports (TCP Attacks)')
            ax6.set_xlabel('Destination Port')
            ax6.set_ylabel('Flow Count')
            ax6.tick_params(axis='x', rotation=45)
        
        plt.tight_layout()
        
        # Save visualizations
        viz_file = self.output_dir / f"analysis_visualizations_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        plt.savefig(viz_file, dpi=300, bbox_inches='tight')
        logger.info(f"Visualizations saved to: {viz_file}")
        
        # Create additional heatmap for correlation analysis
        self.create_correlation_heatmap(df)
        
        return viz_file

    def create_correlation_heatmap(self, df):
        """Create correlation heatmap for key features"""
        logger.info("Creating correlation heatmap...")
        
        # Select key numeric features for correlation analysis
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        key_features = [col for col in numeric_cols if col in [
            'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts', 'flow_pkts_s',
            'fwd_pkts_s', 'bwd_pkts_s', 'pkt_len_mean', 'pkt_len_std',
            'flow_iat_mean', 'flow_iat_std', 'fwd_iat_mean', 'bwd_iat_mean',
            'syn_flag_cnt', 'ack_flag_cnt', 'fin_flag_cnt'
        ]]
        
        if len(key_features) > 5:  # Only create if we have enough features
            correlation_df = df[key_features].corr()
            
            plt.figure(figsize=(12, 10))
            sns.heatmap(correlation_df, annot=True, cmap='coolwarm', center=0,
                       square=True, linewidths=0.5, cbar_kws={"shrink": .5})
            plt.title('Feature Correlation Heatmap')
            plt.tight_layout()
            
            heatmap_file = self.output_dir / f"correlation_heatmap_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(heatmap_file, dpi=300, bbox_inches='tight')
            logger.info(f"Correlation heatmap saved to: {heatmap_file}")
            plt.close()

    def run_complete_analysis(self, df):
        """Run complete validation analysis on dataset"""
        logger.info("Starting comprehensive dataset analysis...")
        
        # Run all analysis methods
        self.analyze_attack_distribution(df)
        self.analyze_protocol_correctness(df)
        self.analyze_flow_characteristics(df)
        self.analyze_tcp_flags(df)
        self.analyze_enhanced_features(df)
        self.analyze_labels_consistency(df)
        self.generate_summary_report(df)
        
        # Create visualizations
        self.create_visualizations(df)
        
        logger.info("Analysis complete!")

    # =============================================================================
    # MAIN WORKFLOW METHODS
    # =============================================================================
    
    def extract_and_validate(self):
        """Complete workflow: extract features from PCAPs and validate the dataset"""
        logger.info("Starting complete CICFlow analysis workflow...")
        
        # Step 1: Extract features from PCAP files
        logger.info("Step 1: Extracting features from PCAP files...")
        if not self.extract_all_features():
            logger.error("Feature extraction failed!")
            return False
        
        # Step 2: Validate the extracted dataset
        logger.info("Step 2: Validating extracted dataset...")
        if self.extracted_df is not None:
            self.run_complete_analysis(self.extracted_df)
        else:
            logger.error("No extracted dataset available for validation!")
            return False
        
        logger.info("Complete analysis workflow finished successfully!")
        return True

    def validate_existing_dataset(self, csv_path):
        """Validate an existing CICFlow dataset"""
        logger.info(f"Validating existing dataset: {csv_path}")
        
        df = self.load_dataset(csv_path)
        if df is None:
            return False
        
        self.run_complete_analysis(df)
        return True

def main():
    parser = argparse.ArgumentParser(
        description='CICFlow Analyzer - Combined Feature Extraction and Validation Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract features from PCAPs and validate
  python cicflow_analyzer.py extract --pcap-dir /path/to/pcaps --output-dir analysis_output
  
  # Validate existing dataset
  python cicflow_analyzer.py validate --csv-file dataset.csv --output-dir analysis_output
  
  # Complete workflow: extract and validate
  python cicflow_analyzer.py complete --pcap-dir /path/to/pcaps --output-dir analysis_output
        """
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Operation mode')
    
    # Extract mode
    extract_parser = subparsers.add_parser('extract', help='Extract features from PCAP files')
    extract_parser.add_argument('--pcap-dir', required=True, help='Directory containing PCAP files')
    extract_parser.add_argument('--output-dir', default='cicflow_analysis', help='Output directory')
    
    # Validate mode
    validate_parser = subparsers.add_parser('validate', help='Validate existing CICFlow dataset')
    validate_parser.add_argument('--csv-file', required=True, help='Path to CICFlow features CSV file')
    validate_parser.add_argument('--output-dir', default='cicflow_analysis', help='Output directory')
    
    # Complete mode
    complete_parser = subparsers.add_parser('complete', help='Complete workflow: extract and validate')
    complete_parser.add_argument('--pcap-dir', required=True, help='Directory containing PCAP files')
    complete_parser.add_argument('--output-dir', default='cicflow_analysis', help='Output directory')
    
    args = parser.parse_args()
    
    if not args.mode:
        parser.print_help()
        sys.exit(1)
    
    # Initialize analyzer
    if args.mode in ['extract', 'complete']:
        analyzer = CICFlowAnalyzer(pcap_dir=args.pcap_dir, output_dir=args.output_dir)
    else:
        analyzer = CICFlowAnalyzer(output_dir=args.output_dir)
    
    # Execute based on mode
    success = False
    
    if args.mode == 'extract':
        success = analyzer.extract_all_features()
    elif args.mode == 'validate':
        success = analyzer.validate_existing_dataset(args.csv_file)
    elif args.mode == 'complete':
        success = analyzer.extract_and_validate()
    
    if success:
        print(f"\n[OK] {args.mode.title()} completed successfully!")
        print(f"[DIR] Output directory: {analyzer.output_dir}")
    else:
        print(f"\n[FAIL] {args.mode.title()} failed!")
        sys.exit(1)

if __name__ == '__main__':
    main()