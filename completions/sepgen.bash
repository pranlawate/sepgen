# Bash completion for sepgen
# Install to /usr/share/bash-completion/completions/sepgen

_sepgen() {
    local cur prev words cword
    _init_completion || return

    local subcommands="analyze trace refine"
    local global_opts="--help"
    local analyze_opts="--name --exec-path -v --verbose --help"
    local trace_opts="--name --args --pid -y --auto-merge -v --verbose --help"
    local refine_opts="--name --audit-log --auto -v --verbose --help"

    local subcmd=""
    local i
    for ((i=1; i < cword; i++)); do
        case "${words[i]}" in
            analyze|trace|refine)
                subcmd="${words[i]}"
                break
                ;;
        esac
    done

    # Complete paths after path-expecting options
    if [[ "$prev" == "--exec-path" || "$prev" == "--audit-log" ]]; then
        _filedir
        return
    fi

    # Complete module name after --name
    if [[ "$prev" == "--name" ]]; then
        return
    fi

    # Complete PID after --pid
    if [[ "$prev" == "--pid" ]]; then
        return
    fi

    case "$subcmd" in
        analyze)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$analyze_opts" -- "$cur"))
            else
                _filedir -d
            fi
            ;;
        trace)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$trace_opts" -- "$cur"))
            else
                _filedir
            fi
            ;;
        refine)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$refine_opts" -- "$cur"))
            fi
            ;;
        "")
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$global_opts" -- "$cur"))
            else
                COMPREPLY=($(compgen -W "$subcommands" -- "$cur"))
            fi
            ;;
    esac
}

complete -F _sepgen sepgen
