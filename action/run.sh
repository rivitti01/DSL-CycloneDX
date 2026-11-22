#!/usr/bin/env bash
# Runs sbom-dsl for the GitHub Action (see action.yml). Inputs arrive as INPUT_* environment
# variables, never interpolated into the script, so a query cannot inject shell code.
#
# sbom-dsl exit codes: 0 = all policies passed, 1 = an ASSERT NO policy was violated, 2 = error.
set -eo pipefail

bin="${SBOM_DSL_BIN:?SBOM_DSL_BIN is not set}"
output_file="${GITHUB_OUTPUT:-/dev/stdout}"
summary_file="${GITHUB_STEP_SUMMARY:-/dev/null}"
results_dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/sbom-dsl-results"
max_summary_bytes=65536

lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

# Escapes a message for a workflow command (::error::, ::warning::).
escape_data() {
    local s="$1"
    s="${s//'%'/%25}"
    s="${s//$'\r'/%0D}"
    s="${s//$'\n'/%0A}"
    printf '%s' "$s"
}

strip_ansi() { sed "s/$(printf '\033')\[[0-9;]*m//g"; }

set_output() { echo "$1=$2" >> "$output_file"; }

input_error() {
    echo "::error title=sbom-dsl::$(escape_data "$1")"
    set_output result error
    set_output exit-code 2
    exit 2
}

query="${INPUT_QUERY:-}"
query_file="${INPUT_QUERY_FILE:-}"
bom="${INPUT_BOM:-}"
format="$(lower "${INPUT_FORMAT:-table}")"
explain="$(lower "${INPUT_EXPLAIN:-false}")"
fail_on_violation="$(lower "${INPUT_FAIL_ON_VIOLATION:-true}")"
job_summary="$(lower "${INPUT_JOB_SUMMARY:-true}")"

# Make sbom-dsl available to the following steps of the job.
if [ -n "${GITHUB_PATH:-}" ]; then
    dirname "$bin" >> "$GITHUB_PATH"
fi

if [ -n "$query" ] && [ -n "$query_file" ]; then
    input_error "Set either 'query' or 'query-file', not both."
fi
if [ -z "$query" ] && [ -z "$query_file" ]; then
    echo "::notice title=sbom-dsl::No query given: sbom-dsl was installed at $bin and added to PATH."
    set_output result installed
    set_output exit-code 0
    exit 0
fi

case "$format" in
    table | json | tree | dot | mermaid) ;;
    *) input_error "Unknown format '$format'. Use table, json, tree, dot or mermaid." ;;
esac
if [ -n "$query_file" ] && [ ! -f "$query_file" ]; then
    input_error "Query file '$query_file' not found (working directory: $PWD)."
fi
if [ -n "$bom" ] && [ ! -f "$bom" ]; then
    input_error "SBOM file '$bom' not found (working directory: $PWD)."
fi

args=(--format "$format")
[ -n "$bom" ] && args+=(--bom "$bom")
[ "$explain" = "true" ] && args+=(--explain)
if [ -n "$query" ]; then
    args+=(-c "$query")
else
    args+=("$query_file")
fi

mkdir -p "$results_dir"
stdout_file="$(mktemp "$results_dir/output.XXXXXX")"
stderr_file="$(mktemp "$results_dir/stderr.XXXXXX")"

set +e
"$bin" "${args[@]}" > "$stdout_file" 2> "$stderr_file"
code=$?
set -e

cat "$stdout_file"
if [ -s "$stderr_file" ]; then
    cat "$stderr_file" >&2
fi

case "$code" in
    0) result=passed ;;
    1) result=violation ;;
    *) result=error ;;
esac
set_output result "$result"
set_output exit-code "$code"
set_output output-file "$stdout_file"

# Annotations, shown on the workflow run and on pull requests.
if [ "$result" = "violation" ]; then
    level=error
    [ "$fail_on_violation" = "true" ] || level=warning
    failed="$(grep -F '[POLICY ASSERTION FAILED]' "$stdout_file" | sed 's/^\[POLICY ASSERTION FAILED\] *//' || true)"
    if [ -n "$failed" ]; then
        while IFS= read -r policy; do
            echo "::$level title=SBOM policy violated::$(escape_data "$policy")"
        done <<< "$failed"
    else
        echo "::$level title=SBOM policy violated::One or more ASSERT NO policies failed. See the step log."
    fi
elif [ "$result" = "error" ]; then
    diagnostics="$(strip_ansi < "$stderr_file" | awk 'NF && !seen[$0]++' | head -n 10 || true)"
    echo "::error title=sbom-dsl failed (exit code $code)::$(escape_data "${diagnostics:-sbom-dsl exited with code $code}")"
fi

# Job summary.
if [ "$job_summary" = "true" ]; then
    case "$result" in
        passed) status="✅ Passed" ;;
        violation) status="❌ Policy violated" ;;
        *) status="⚠️ Error (exit code $code)" ;;
    esac
    fence_lang=text
    case "$format" in
        json) fence_lang=json ;;
        dot) fence_lang="dot" ;;
    esac
    {
        echo "### SBOM DSL: $status"
        echo
        if [ -n "$query_file" ]; then
            echo "**Query file:** \`$query_file\`"
        else
            echo '```sql'
            printf '%s\n' "$query"
            echo '```'
        fi
        [ -n "$bom" ] && echo "**SBOM:** \`$bom\`"
        echo
        if [ -s "$stdout_file" ]; then
            if [ "$format" = "mermaid" ] && [ "$explain" != "true" ]; then
                # One fenced block per graph, so that GitHub renders each diagram.
                head -c "$max_summary_bytes" "$stdout_file" | awk '
                    /^graph / { if (open) print "```"; print "```mermaid"; open = 1 }
                    { if (open) print; else other = other $0 "\n" }
                    END { if (open) print "```"; if (other != "") printf "```text\n%s```\n", other }'
            else
                echo "\`\`\`$fence_lang"
                head -c "$max_summary_bytes" "$stdout_file"
                echo
                echo '```'
            fi
            if [ "$(wc -c < "$stdout_file")" -gt "$max_summary_bytes" ]; then
                echo
                echo "_Output truncated to $max_summary_bytes bytes; the full output is in the step log._"
            fi
        fi
        if [ -s "$stderr_file" ]; then
            echo
            echo '<details><summary>Diagnostics</summary>'
            echo
            echo '```text'
            strip_ansi < "$stderr_file"
            echo '```'
            echo '</details>'
        fi
        echo
    } >> "$summary_file"
fi

if [ "$result" = "violation" ] && [ "$fail_on_violation" != "true" ]; then
    exit 0
fi
exit "$code"
