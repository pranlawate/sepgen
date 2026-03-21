import argparse
from pathlib import Path
from typing import Optional


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='sepgen',
        description='SELinux policy generator with static analysis and runtime tracing'
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    analyze_parser = subparsers.add_parser('analyze', help='Generate policy from static source code analysis')
    analyze_parser.add_argument('source_path', help='Path to source code directory or file')
    analyze_parser.add_argument('--name', help='Policy module name (default: derived from source)', default=None)
    analyze_parser.add_argument('--exec-path', help='Installed binary path for .fc entry (e.g. /usr/sbin/setrans)', default=None)
    analyze_parser.add_argument('-v', '--verbose', action='count', default=0,
                                help='Increase verbosity (-v for verbose, -vv for debug)')

    trace_parser = subparsers.add_parser('trace', help='Generate policy from strace runtime tracing')
    trace_parser.add_argument('binary', help='Path to binary to trace')
    trace_parser.add_argument('--name', help='Policy module name', default=None)
    trace_parser.add_argument('--args', help='Arguments to pass to the binary', default='')
    trace_parser.add_argument('--pid', type=int, help='Attach to existing process ID', default=None)
    trace_parser.add_argument('-y', '--auto-merge', action='store_true',
                              help='Auto-approve merge conflicts (trace wins)')
    trace_parser.add_argument('-v', '--verbose', action='count', default=0,
                              help='Increase verbosity (-v for verbose, -vv for debug)')

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = create_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    if args.command == 'analyze':
        return run_analyze(args)
    elif args.command == 'trace':
        return run_trace(args)

    return 0


def run_analyze(args) -> int:
    """Execute analyze command"""
    from sepgen.analyzer.c_analyzer import CAnalyzer
    from sepgen.analyzer.service_detector import ServiceDetector
    from sepgen.intent.classifier import IntentClassifier
    from sepgen.generator.te_generator import TEGenerator
    from sepgen.generator.fc_generator import FCGenerator
    from sepgen.generator.te_writer import TEWriter
    from sepgen.generator.fc_writer import FCWriter

    source_path = Path(args.source_path)
    module_name = args.name or source_path.stem

    print(f"[1/4] Analyzing source... ", end='', flush=True)
    analyzer = CAnalyzer()
    if source_path.is_dir():
        accesses = analyzer.analyze_directory(source_path)
    else:
        accesses = analyzer.analyze_file(source_path)
    print(f"✓")

    service_info = None
    if source_path.is_dir():
        print(f"[2/4] Detecting service files... ", end='', flush=True)
        detector = ServiceDetector()
        service_info = detector.detect_service_files(source_path.parent)
        print(f"✓")
    else:
        print(f"[2/4] Detecting service files... (skipped, single file)")

    exec_path = getattr(args, 'exec_path', None)
    if not exec_path and service_info and service_info.exec_path:
        exec_path = service_info.exec_path

    print(f"[3/4] Classifying intents... ", end='', flush=True)
    classifier = IntentClassifier()
    intents = classifier.classify(accesses)
    print(f"✓")

    if args.verbose >= 1:
        for intent in intents:
            print(f"  • {intent.intent_type.value}: {intent.accesses[0].path}")

    print(f"[4/4] Generating policy... ", end='', flush=True)

    te_gen = TEGenerator(module_name)
    policy = te_gen.generate(intents, service_info=service_info)

    fc_gen = FCGenerator(module_name, exec_path=exec_path)
    contexts = fc_gen.generate(intents, service_info=service_info)

    te_writer = TEWriter()
    fc_writer = FCWriter()

    te_path = Path(f"{module_name}.te")
    fc_path = Path(f"{module_name}.fc")

    te_writer.write(policy, te_path)
    fc_writer.write(contexts, fc_path)

    print(f"✓")
    print(f"Generated: {te_path} ({len(policy.types)} types), {fc_path} ({len(contexts.entries)} entries)")

    return 0


def run_trace(args) -> int:
    """Execute trace command"""
    from sepgen.tracer.process_tracer import ProcessTracer
    from sepgen.tracer.strace_parser import StraceParser
    from sepgen.intent.classifier import IntentClassifier
    from sepgen.generator.te_generator import TEGenerator
    from sepgen.generator.fc_generator import FCGenerator
    from sepgen.generator.te_writer import TEWriter
    from sepgen.generator.fc_writer import FCWriter
    from sepgen.merger.policy_merger import PolicyMerger

    binary_path = Path(args.binary)
    module_name = args.name or binary_path.stem

    merger = PolicyMerger()
    existing_te, existing_fc = merger.detect_existing_policy(module_name)

    if existing_te:
        print(f"\nFound existing policy: {existing_te}")

    print(f"[1/4] Tracing process... ", end='', flush=True)

    tracer = ProcessTracer()
    strace_file = tracer.trace(
        binary=args.binary if not args.pid else None,
        args=args.args,
        pid=args.pid
    )

    print(f"✓")
    print(f"[2/4] Parsing syscalls... ", end='', flush=True)

    parser = StraceParser()
    accesses = parser.parse_file(strace_file)

    print(f"✓")
    print(f"[3/4] Classifying intents... ", end='', flush=True)

    classifier = IntentClassifier()
    intents = classifier.classify(accesses)

    print(f"✓")

    if args.verbose >= 1:
        for intent in intents:
            print(f"  • {intent.intent_type.value}: {intent.accesses[0].path}")

    print(f"[4/4] Generating policy... ", end='', flush=True)

    te_gen = TEGenerator(module_name)
    new_policy = te_gen.generate(intents)

    fc_gen = FCGenerator(module_name, exec_path=args.binary)
    new_contexts = fc_gen.generate(intents)

    if existing_te:
        print(f"✓")
        print("\nComparing with runtime trace...")

        existing_policy = merger.load_existing_policy(existing_te)
        report = merger.compare(existing_policy, new_policy)

        print(f"\nComparison:")
        print(f"  Static analysis: {len(existing_policy.types)} types")
        print(f"  Runtime trace:   {len(new_policy.types)} types")
        print(f"  Matched:        {len(report.matched_types)} types")

        if report.conflicts:
            print(f"\nConflicts found: {len(report.conflicts)}")
            for conflict in report.conflicts:
                print(f"  • {conflict['name']}")
                print(f"    Existing: {conflict['existing']}")
                print(f"    Trace:    {conflict['new']}")

        if args.auto_merge:
            print("\nMerging policies (auto-approved)... ", end='', flush=True)
            final_policy = merger.merge(existing_policy, new_policy, auto_approve=True)
            print("✓")
        else:
            response = input("\nMerge with trace results? [Y/n/diff] ").strip().lower()
            if response in ['y', '']:
                final_policy = merger.merge(existing_policy, new_policy, auto_approve=True)
            else:
                print("Skipping merge.")
                return 0

        backup_te = Path(f"{module_name}.te.backup")
        backup_fc = Path(f"{module_name}.fc.backup")
        existing_te.rename(backup_te)
        if existing_fc:
            existing_fc.rename(backup_fc)

        print(f"Backup saved: {backup_te}")
    else:
        final_policy = new_policy
        print(f"✓")

    te_writer = TEWriter()
    fc_writer = FCWriter()

    te_path = Path(f"{module_name}.te")
    fc_path = Path(f"{module_name}.fc")

    te_writer.write(final_policy, te_path)
    fc_writer.write(new_contexts, fc_path)

    print(f"\nGenerated: {te_path} ({len(final_policy.types)} types), {fc_path} ({len(new_contexts.entries)} entries)")

    return 0
