package cli

import (
	"fmt"
	"strings"
)

// Completion prints a script for the selected shell. Flags come from command
// help at completion time so an installed script survives binary upgrades.
func Completion(args []string) error {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Println("Usage: flugschreiber completion <bash|powershell>")
		return nil
	}
	if len(args) != 1 {
		return fmt.Errorf("completion: choose a shell: bash or powershell")
	}
	var script string
	switch args[0] {
	case "bash":
		script = bashCompletion
	case "powershell":
		script = powershellCompletion
	default:
		return fmt.Errorf("completion: unsupported shell %q; use bash or powershell", args[0])
	}
	script = strings.ReplaceAll(script, "@COMMANDS@", strings.Join(commandNames, " "))
	fmt.Print(script)
	return nil
}

const bashCompletion = `_flugschreiber() {
    local cur="${COMP_WORDS[COMP_CWORD]}" cmd="${COMP_WORDS[1]}" word
    local -a choices=() args=()
    COMPREPLY=()
    if (( COMP_CWORD == 1 )); then
        choices=(@COMMANDS@)
    elif [[ "$cmd" == completion ]] && (( COMP_CWORD == 2 )); then
        choices=(bash powershell)
    elif [[ "$cmd" == keys ]] && (( COMP_CWORD == 2 )); then
        choices=(list rotate retire)
    elif [[ "$cur" == -* ]]; then
        case " @COMMANDS@ " in
            *" $cmd "*) args=("$cmd") ;;
            *) return ;;
        esac
        if [[ "$cmd" == keys ]]; then
            case "${COMP_WORDS[2]}" in
                list|rotate|retire) args+=("${COMP_WORDS[2]}") ;;
                *) return ;;
            esac
        fi
        choices=(--help)
        while read -r word _; do
            [[ "$word" =~ ^-[a-z][a-z0-9-]*$ ]] && choices+=("-$word")
        done < <("${COMP_WORDS[0]}" "${args[@]}" --help 2>&1)
    fi
    for word in "${choices[@]}"; do
        [[ "$word" == "$cur"* ]] && COMPREPLY+=("$word")
    done
    return 0
}
complete -o default -F _flugschreiber flugschreiber flugschreiber.exe
`

const powershellCompletion = `Register-ArgumentCompleter -Native -CommandName flugschreiber, flugschreiber.exe -ScriptBlock {
    param($wordToComplete, $commandAst, $cursorPosition)
    $elements = @($commandAst.CommandElements | Where-Object { $_.Extent.StartOffset -lt $cursorPosition })
    $index = $elements.Count
    if ($wordToComplete) { $index-- }
    $commands = '@COMMANDS@'.Split(' ')
    $choices = @()
    $cmd = if ($elements.Count -gt 1) { $elements[1].Extent.Text } else { '' }
    if ($index -eq 1) {
        $choices = $commands
    } elseif ($cmd -eq 'completion' -and $index -eq 2) {
        $choices = @('bash', 'powershell')
    } elseif ($cmd -eq 'keys' -and $index -eq 2) {
        $choices = @('list', 'rotate', 'retire')
    } elseif ($wordToComplete.StartsWith('-') -and $commands -contains $cmd) {
        $helpArgs = @($cmd)
        if ($cmd -eq 'keys') {
            $sub = $elements[2].Extent.Text
            if ($sub -notin @('list', 'rotate', 'retire')) { return }
            $helpArgs += $sub
        }
        $exe = $elements[0].Value
        if (-not $exe) { return }
        $choices = @('--help')
        & $exe @helpArgs --help 2>&1 | ForEach-Object {
            if ($_ -match '^\s+-([a-z][a-z0-9-]*)(?:\s|$)') { $choices += '--' + $Matches[1] }
        }
    }
    $choices | Where-Object { $_.StartsWith($wordToComplete, [StringComparison]::OrdinalIgnoreCase) } | ForEach-Object {
        [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
    }
}
`
