import os
import sys
import time
import shutil
import argparse
import subprocess
from pathlib import Path
from datetime import datetime
import pandas as pd
import re
import logging
from src.utils.dataset_combiner import combine_datasets


def main():
    parser = argparse.ArgumentParser(description="Run main.py multiple times with different output directories (4-subnet topology)")
    parser.add_argument('--runs', type=int, default=4, help='Number of times to run main.py (default: 4)')
    parser.add_argument('--config', type=str, default='config.json', help='Configuration file to use (default: config.json)')
    parser.add_argument('--cores', type=int, help='Number of CPU cores for PCAP processing')
    parser.add_argument('--max-cores', type=int, help='Maximum number of CPU cores available')
    parser.add_argument('--combine', action='store_true', default=True, help='Combine datasets after all runs complete (default: True)')
    parser.add_argument('--no-combine', action='store_true', help='Skip dataset combination')
    parser.add_argument('--no-pcap', action='store_true', help='Skip PCAP file combination (combine CSV only)')
    args = parser.parse_args()
    
    # Handle combine logic
    if args.no_combine:
        args.combine = False

    # Handle PCAP combination logic
    combine_pcap = args.combine and not args.no_pcap

    # Check for admin privileges (cross-platform)
    try:
        import ctypes
        if sys.platform == "win32":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("ERROR: This script must be run as administrator on Windows.")
                sys.exit(1)
        else:
            if os.geteuid() != 0:
                print("ERROR: This script must be run as root for Mininet.")
                sys.exit(1)
    except Exception:
        print("WARNING: Could not verify admin privileges.")
        pass

    base_dir = Path(__file__).parent.resolve()
    main_script = base_dir / "main.py"

    if not main_script.exists():
        print(f"ERROR: main.py not found at {main_script}")
        sys.exit(1)

    config_file = base_dir / args.config
    if not config_file.exists():
        print(f"ERROR: Config file not found at {config_file}")
        sys.exit(1)

    print(f"[RUN] Starting {args.runs} runs of main.py (4-Subnet Enterprise Topology)")
    print(f"Using config file: {config_file}")
    print(f"Base directory: {base_dir}")
    print("[GLOBAL] Network Configuration:")
    print("   - h1: 192.168.10.0/24 (Isolated/External Network)")
    print("   - h2-h5: 192.168.20.0/24 (Corporate Internal Network)")
    print("   - h6: 192.168.30.0/24 (Server/DMZ Network)")
    print("   - Controller: 192.168.0.0/24 (Management Network)")
    print("==" * 30)

    successful_runs = 0
    failed_runs = 0
    run_results = []

    date_str = datetime.now().strftime('%d%m%y')
    output_base = base_dir / "main_output"

    existing_dirs = []
    if output_base.exists():
        for dir_path in output_base.iterdir():
            if dir_path.is_dir() and dir_path.name.startswith(f"{date_str}-"):
                try:
                    run_id = int(dir_path.name.split('-')[1])
                    existing_dirs.append(run_id)
                except (ValueError, IndexError):
                    continue

    start_id = 1
    if existing_dirs:
        start_id = max(existing_dirs) + 1
        print(f"Found existing directories up to {date_str}-{max(existing_dirs)}")
        print(f"Starting with {date_str}-{start_id}")

    for run_num in range(start_id, start_id + args.runs):
        actual_run_index = run_num - start_id + 1
        print(f"\n[RUN] Starting v1.0 Run {actual_run_index}/{args.runs} (ID: {date_str}-{run_num})")
        print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"[NETWORK] 4-Subnet Enterprise Topology with Layer 3 Routing")

        output_dir = base_dir / f"main_output" / f"{date_str}-{run_num}"

        if output_dir.exists():
            print(f"WARNING: Directory {output_dir} already exists! Skipping this run.")
            continue

        output_dir.mkdir(parents=True, exist_ok=True)

        temp_script = base_dir / f"main_run_{run_num}.py"

        try:
            with open(main_script, 'r') as f:
                script_content = f.read()

            original_line = 'OUTPUT_DIR = BASE_DIR / "main_output"'
            new_line = f'OUTPUT_DIR = BASE_DIR / "main_output" / "{date_str}-{run_num}"'
            modified_content = script_content.replace(original_line, new_line)

            with open(temp_script, 'w') as f:
                f.write(modified_content)

            os.chmod(temp_script, 0o755)

            cmd = [sys.executable, str(temp_script), str(config_file)]

            if args.cores:
                cmd.extend(['--cores', str(args.cores)])
            if args.max_cores:
                cmd.extend(['--max-cores', str(args.max_cores)])

            print(f"Command: {' '.join(cmd)}")
            print(f"Output directory: {output_dir}")

            start_time = time.time()
            result = subprocess.run(cmd, cwd=base_dir)
            end_time = time.time()

            execution_time = end_time - start_time

            if result.returncode == 0:
                print(f"[OK] v1.0 Run {actual_run_index} (ID: {date_str}-{run_num}) completed successfully")
                print(f"[TIME]  Execution time: {execution_time:.2f} seconds ({execution_time/60:.2f} minutes)")
                print(f"[NETWORK] 4-Subnet topology dataset generated successfully")
                successful_runs += 1
                status = "SUCCESS"
            else:
                print(f"[FAIL] v1.0 Run {actual_run_index} (ID: {date_str}-{run_num}) failed with return code {result.returncode}")
                print(f"[TIME]  Execution time: {execution_time:.2f} seconds ({execution_time/60:.2f} minutes)")
                failed_runs += 1
                status = "FAILED"

            run_results.append({
                'run': actual_run_index,
                'run_id': f"{date_str}-{run_num}",
                'status': status,
                'execution_time': execution_time,
                'output_dir': output_dir,
                'return_code': result.returncode
            })

        except Exception as e:
            print(f"[FAIL] v1.0 Run {actual_run_index} (ID: {date_str}-{run_num}) failed with exception: {e}")
            failed_runs += 1
            run_results.append({
                'run': actual_run_index,
                'run_id': f"{date_str}-{run_num}",
                'status': 'EXCEPTION',
                'execution_time': 0,
                'output_dir': output_dir,
                'return_code': -1,
                'error': str(e)
            })

        finally:
            if temp_script.exists():
                temp_script.unlink()

        print(f"v1.0 Run {actual_run_index} (ID: {date_str}-{run_num}) completed")
        print("-" * 50)

    print("\n" + "=" * 70)
    print("=" * 70)
    print(f"[RUN] UKMDDoSDN Dataset Generation Framework")
    print(f"[NETWORK] Network Architecture: Layer 3 routing across 4 subnets")
    print(f"[STATS] Total runs: {args.runs}")
    print(f"[OK] Successful runs: {successful_runs}")
    print(f"[FAIL] Failed runs: {failed_runs}")
    print(f"[CHART] Success rate: {(successful_runs/args.runs)*100:.1f}%")

    print("\nDetailed Results:")
    for result in run_results:
        status_emoji = "[OK]" if result['status'] == "SUCCESS" else "[FAIL]"
        run_id = result.get('run_id', f"{date_str}-{result['run']}")
        print(f"  {status_emoji} v1.0 Run {result['run']} (ID: {run_id}): {result['status']} "
              f"({result['execution_time']:.1f}s) -> {result['output_dir'].name}")
        if 'error' in result:
            print(f"    Error: {result['error']}")

    print(f"\n[DIR] Output directories created in: {base_dir / 'main_output'}")
    if run_results:
        first_id = run_results[0].get('run_id', f"{date_str}-1")
        last_id = run_results[-1].get('run_id', f"{date_str}-{len(run_results)}")
        print(f"[DIR]  Dataset directories: {first_id} to {last_id}")

    print("\n[GLOBAL] 4-Subnet Network Configuration:")
    print("   - h1: 192.168.10.0/24 (Isolated/External Network)")
    print("   - h2-h5: 192.168.20.0/24 (Corporate Internal Network)")
    print("   - h6: 192.168.30.0/24 (Server/DMZ Network)")
    print("   - Controller: 192.168.0.0/24 (Management Network)")

    print("\n[TARGET] Attack Scenarios Supported:")
    print("   - Inter-subnet DDoS attacks (h1 -> h6, h2-h5 -> h6)")
    print("   - Cross-network lateral movement")
    print("   - Enterprise network segmentation testing")
    print("   - Layer 3 routing attack scenarios")

    # Combine datasets if requested
    if args.combine and successful_runs > 0:
        combine_success = combine_datasets(output_base, include_pcap=combine_pcap)
        if not combine_success:
            print("\n[WARN] Dataset combination failed!")

    if failed_runs > 0:
        print(f"\n[WARN]  WARNING: {failed_runs} runs failed!")
        sys.exit(1)
    else:
        print("\n[DONE] All 4-subnet enterprise topology runs completed successfully!")
        if args.combine and successful_runs > 0:
            if combine_pcap:
                print("[NOTES] Datasets and PCAP files with realistic enterprise network scenarios generated and combined.")
            else:
                print("[NOTES] Datasets with realistic enterprise network scenarios generated and combined (CSV only).")
        else:
            print("[NOTES] Datasets with realistic enterprise network scenarios generated.")
        sys.exit(0)

if __name__ == "__main__":
    main()