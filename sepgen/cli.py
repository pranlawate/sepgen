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

    refine_parser = subparsers.add_parser('refine', help='Refine policy from AVC denials')
    refine_parser.add_argument('--name', required=True, help='Policy module name')
    refine_parser.add_argument('--audit-log', default='/var/log/audit/audit.log',
                               help='Path to audit log (default: /var/log/audit/audit.log)')
    refine_parser.add_argument('--auto', action='store_true',
                               help='Auto-apply suggestions to .te file')
    refine_parser.add_argument('-v', '--verbose', action='count', default=0,
                               help='Increase verbosity')

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
    elif args.command == 'refine':
        return run_refine(args)

    return 0


def run_analyze(args) -> int:
    """Execute analyze command"""
    from sepgen.analyzer.project_scanner import ProjectScanner
    from sepgen.intent.classifier import IntentClassifier
    from sepgen.generator.te_generator import TEGenerator
    from sepgen.generator.fc_generator import FCGenerator
    from sepgen.generator.te_writer import TEWriter
    from sepgen.generator.fc_writer import FCWriter

    source_path = Path(args.source_path)
    module_name = args.name or source_path.stem

    print(f"[1/3] Scanning project... ", end='', flush=True)
    scanner = ProjectScanner()
    project = scanner.scan(source_path, module_name)
    print(f"✓")

    exec_path = getattr(args, 'exec_path', None) or project.exec_path

    if args.verbose >= 2 and exec_path:
        print(f"  exec_path: {exec_path}")

    print(f"[2/3] Classifying intents... ", end='', flush=True)
    classifier = IntentClassifier()
    intents = classifier.classify(project.accesses)
    print(f"✓")

    if args.verbose >= 1:
        for intent in intents:
            print(f"  • {intent.intent_type.value}: {intent.accesses[0].path}")

    print(f"[3/3] Generating policy... ", end='', flush=True)

    te_gen = TEGenerator(module_name)
    policy = te_gen.generate(intents, service_info=project.service_info, build_info=project.build_info)

    fc_gen = FCGenerator(module_name, exec_path=exec_path)
    contexts = fc_gen.generate(intents, service_info=project.service_info, build_info=project.build_info)

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

    filtered = [a for a in accesses if not merger.is_system_path(a.path)]

    print(f"[4/4] Generating policy... ", end='', flush=True)

    te_gen = TEGenerator(module_name)
    new_policy = te_gen.generate(intents)

    fc_gen = FCGenerator(module_name, exec_path=args.binary)
    new_contexts = fc_gen.generate(intents)

    trace_fc = [e for e in new_contexts.entries if not merger.is_system_path(e.path)]
    new_contexts.entries = trace_fc

    if existing_te:
        print(f"✓")
        print("\nComparing with runtime trace...")

        existing_policy = merger.load_existing_policy(existing_te)
        report = merger.compare(existing_policy, new_policy)

        print(f"\nComparison:")
        print(f"  Static analysis: {len(existing_policy.types)} types")
        print(f"  Runtime trace:   {len(new_policy.types)} types")
        print(f"  Matched:         {len(report.matched_types)} types")
        if report.new_types:
            print(f"  New from trace:  {', '.join(t.name for t in report.new_types)}")
        if report.new_allow_rules:
            print(f"  New rules:       {len(report.new_allow_rules)}")

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

        from sepgen.models.policy import FileContexts
        from sepgen.generator.fc_writer import FCWriter as FCW
        if existing_fc:
            existing_fc_content = existing_fc.read_text()
            existing_paths = set()
            for line in existing_fc_content.strip().split('\n'):
                if line.strip():
                    parts = line.split('\t')
                    if parts:
                        existing_paths.add(parts[0].strip())
            for entry in new_contexts.entries:
                if entry.path not in existing_paths:
                    existing_fc_content += f"\n{entry}"
            final_fc_content = existing_fc_content
        else:
            final_fc_content = None

        backup_te = Path(f"{module_name}.te.backup")
        backup_fc = Path(f"{module_name}.fc.backup")
        existing_te.rename(backup_te)
        if existing_fc:
            existing_fc.rename(backup_fc)

        print(f"Backup saved: {backup_te}")
    else:
        final_policy = new_policy
        final_fc_content = None
        print(f"✓")

    te_writer = TEWriter()
    fc_writer = FCWriter()

    te_path = Path(f"{module_name}.te")
    fc_path = Path(f"{module_name}.fc")

    te_writer.write(final_policy, te_path)

    if final_fc_content:
        fc_path.write_text(final_fc_content + "\n")
    else:
        fc_writer.write(new_contexts, fc_path)

    print(f"\nGenerated: {te_path} ({len(final_policy.types)} types), {fc_path}")

    return 0


def run_refine(args) -> int:
    """Execute refine command — read AVC denials and suggest policy additions."""
    from sepgen.refiner.denial_reader import DenialReader
    from sepgen.refiner.macro_suggester import MacroSuggester

    module_name = args.name
    module_type = f"{module_name}_t"
    audit_log = Path(args.audit_log)
    te_path = Path(f"{module_name}.te")

    if not audit_log.exists():
        print(f"Error: Audit log not found: {audit_log}")
        return 1

    print(f"[1/3] Reading AVC denials for {module_type}... ", end='', flush=True)

    reader = DenialReader()
    denials = reader.read_audit_log(audit_log, module_type)

    print(f"✓ ({len(denials)} denials)")

    if not denials:
        print(f"\nNo denials found for {module_type}. Policy is complete!")
        return 0

    if args.verbose >= 1:
        for d in denials:
            print(f"  • {d}")

    print(f"[2/3] Suggesting macros... ", end='', flush=True)

    suggester = MacroSuggester()
    suggestions = suggester.suggest(denials)

    print(f"✓ ({len(suggestions)} suggestions)")

    print(f"\nSuggested additions for {module_name}.te:")
    for s in suggestions:
        print(f"  + {s}")

    if args.auto and te_path.exists():
        print(f"\n[3/3] Updating {te_path}... ", end='', flush=True)

        content = te_path.read_text()
        additions = []
        for s in suggestions:
            line = str(s)
            if line not in content:
                additions.append(line)

        if additions:
            insert_point = content.rindex("########################################")
            policy_section = content[insert_point:]
            new_content = content[:insert_point] + policy_section.rstrip() + "\n"
            for line in additions:
                new_content += line + "\n"

            te_path.write_text(new_content)
            print(f"✓ ({len(additions)} rules added)")
        else:
            print("✓ (no new rules needed)")
    elif args.auto:
        print(f"\nWarning: {te_path} not found. Run analyze/trace first.")
    else:
        print(f"\nTo apply: sepgen refine --name {module_name} --auto")

    return 0
