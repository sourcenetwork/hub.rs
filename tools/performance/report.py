#!/usr/bin/env python3
"""Plot measured workload evidence; never substitute missing measurements with zero."""
import argparse
import json
import math
from pathlib import Path


def load_run(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    records = [json.loads(line) for line in (directory / 'workload.jsonl').read_text().splitlines() if line.strip()]
    def one(kind):
        matches = [row for row in records if row.get('kind') == kind]
        if len(matches) != 1:
            raise ValueError(f'expected one {kind} record, found {len(matches)}')
        return matches[0]
    config, summary = one('configuration'), one('summary')
    if config.get('format_version') != 2:
        raise ValueError('unsupported workload format')
    verification, recovery = one('verification'), one('recovery')
    observations = [row for row in records if row.get('kind') == 'observation']
    passed = (
        manifest.get('exit_code') == 0
        and len(observations) == config['count'] == summary['offered'] == summary['completed_workflows']
        and summary['confirmed'] == config['count']
        and {row.get('index') for row in observations} == set(range(config['count']))
        and all(row.get('outcome') == 'confirmed' and row.get('verification_failure') is False
                and row.get('error') is None for row in observations)
        and all(summary.get(key) == 0 for key in ('verification_failures', 'unknown', 'rejected', 'reverted', 'not_sent', 'confirmed_incomplete_workflows'))
        and verification['verified'] == config['count'] and verification['unresolved'] == 0
        and verification['replicas'] == config['nodes']
        and recovery['inspected_operations'] == config['count']
        and recovery['receipt_mismatches'] == recovery['state_mismatches'] == 0
    )
    latencies = []
    for row in observations:
        value = row.get('scheduled_to_certified_receipt_ms')
        if value is not None:
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
                raise ValueError('invalid receipt latency')
            latencies.append(value)
    resources = one('resource_configuration')
    series = {int(pid): [] for pid in resources['node_pids']}
    missing = 0
    for row in records:
        if row.get('kind') != 'resources':
            continue
        seen = set()
        for raw in row['sample'].get('rows', '').splitlines():
            pid, rss, _ = raw.split()
            pid, rss = int(pid), int(rss)
            if pid not in series or pid in seen or rss < 0:
                raise ValueError('invalid resource sample')
            seen.add(pid)
            series[pid].append((row['elapsed_seconds'], rss / 1024))
        missing += len(series.keys() - seen)
    return manifest, config, summary, passed, latencies, series, missing


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    manifest, config, summary, passed, latencies, series, missing = load_run(args.directory)
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    fig, axes = plt.subplots(1, 2, figsize=(12, 4), layout='constrained')
    ordered = sorted(latencies)
    if ordered:
        axes[0].plot(ordered, [(i + 1) * 100 / len(ordered) for i in range(len(ordered))], color='#237b57')
    else:
        axes[0].text(.5, .5, 'No receipt measurements', ha='center', transform=axes[0].transAxes)
    axes[0].set(xlabel='Scheduled arrival to certified receipt (ms)', ylabel='Measured operations (%)', ylim=(0, 100))
    for index, values in enumerate(series.values()):
        if values:
            axes[1].plot(*zip(*values), label=f'Member {index}')
    axes[1].set(xlabel='Workload elapsed time (s)', ylabel='Resident memory (MiB)')
    if any(series.values()):
        axes[1].legend()
    else:
        axes[1].text(.5, .5, 'No memory measurements', ha='center', transform=axes[1].transAxes)
    for axis in axes:
        axis.grid(alpha=.2)
        axis.spines[['top', 'right']].set_visible(False)
    state = 'Validated workload' if passed else 'FAILED workload — not a capacity result'
    date = manifest.get('measurement_date', manifest.get('started_at', 'Date not recorded'))[:10]
    fig.suptitle(f"Vera · {state} · {date}\n{manifest['source'][:12]} · {manifest['history']} · {config['workload']}")
    fig.savefig(args.directory / 'measurements.svg')
    fig.savefig(args.directory / 'measurements.png', dpi=150)
    plt.close(fig)
    details = {
        'status': 'passed' if passed else 'failed', 'manifest': manifest,
        'configuration': {key: value for key, value in config.items() if key != 'node_data_dirs'},
        'summary': summary, 'missing_member_samples': missing,
        'scope': 'Four members on one host; receipt latency is not consensus finality latency. No maximum capacity or WAN claim.',
    }
    (args.directory / 'report.json').write_text(json.dumps(details, indent=2, allow_nan=False) + '\n')
    (args.directory / 'report.md').write_text(
        f"# Vera performance\n\n{state}.\n\n"
        f"Source: `{manifest['source']}`. Backend: {manifest['history']}.\n\n"
        f"Completed workflows/s: {summary['completed_workflows_per_second']:.2f}. "
        f"Receipt p95: {summary['scheduled_to_certified_receipt_ms']['p95']:.2f} ms.\n\n"
        f"Missing member resource samples: {missing}.\n\n{details['scope']}\n\n"
        '![Measured receipt latency and resident memory](measurements.svg)\n'
    )
    if not passed:
        raise SystemExit('workload correctness or recovery checks failed')


if __name__ == '__main__':
    main()
