#compdef sepgen

_sepgen() {
    local -a subcommands
    subcommands=(
        'analyze:Generate policy from static source code analysis'
        'trace:Generate policy from strace runtime tracing'
        'refine:Refine policy from AVC denials'
    )

    _arguments -C \
        '1:command:->command' \
        '*::arg:->args'

    case $state in
        command)
            _describe 'command' subcommands
            ;;
        args)
            case $words[1] in
                analyze)
                    _arguments \
                        '--name[Policy module name]:name:' \
                        '--exec-path[Installed binary path]:path:_files' \
                        '(-v --verbose)'{-v,--verbose}'[Increase verbosity]' \
                        ':source_path:_files -/'
                    ;;
                trace)
                    _arguments \
                        '--name[Policy module name]:name:' \
                        '--args[Arguments for binary]:args:' \
                        '--pid[Attach to process ID]:pid:' \
                        '(-y --auto-merge)'{-y,--auto-merge}'[Auto-approve merges]' \
                        '(-v --verbose)'{-v,--verbose}'[Increase verbosity]' \
                        ':binary:_files'
                    ;;
                refine)
                    _arguments \
                        '--name[Policy module name]:name:' \
                        '--audit-log[Path to audit log]:path:_files' \
                        '--auto[Auto-apply suggestions]' \
                        '(-v --verbose)'{-v,--verbose}'[Increase verbosity]'
                    ;;
            esac
            ;;
    esac
}

_sepgen
