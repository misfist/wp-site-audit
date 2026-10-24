#!/usr/bin/env bash
#
# Audits WordPress sites over SSH for signs of compromise since a given date.
#
# Each site gets a technical Markdown report (<label>.md) and a draft
# client-facing report (<label>-client.md), and a status summary for all sites
# is printed and saved when the run finishes. Nothing on the remote servers is
# modified.

set -uo pipefail

readonly STATUS_OK=0
readonly STATUS_REVIEW=1
readonly STATUS_FLAG=2
readonly STATUS_ERROR=3
readonly STATUS_LABELS=( 'OK' 'REVIEW' 'FLAG' 'ERROR' )

# Core checksum warnings that are known to be harmless. Matched as an
# extended regular expression against each warning line. Deleting
# readme.html, license.txt and wp-config-sample.php is common hardening.
readonly IGNORED_CORE_WARNINGS='File should not exist: (.*/)?php_errorlog$|File should not exist: wp-includes/\.htaccess$|File doesn.t exist: (readme\.html|license\.txt|wp-config-sample\.php)$'

# An index.php in uploads no larger than this, whose every line matches
# PLACEHOLDER_LINE_PATTERN, is treated as a directory-listing placeholder
# ("Silence is golden") and not reported as a script. Allowed lines are blank
# lines, PHP open and close tags, and // or # comments that contain no "?",
# so code cannot be hidden after a closing tag inside a comment.
readonly PLACEHOLDER_MAX_BYTES=200
readonly PLACEHOLDER_LINE_PATTERN='^[[:space:]]*(<\?php)?[[:space:]]*((//|#)[^?]*)?[[:space:]]*(\?>)?[[:space:]]*$'

sites_file=''
since_date=''
output_directory=''
site_filter=''

# Set for the site currently being audited by audit_site().
site_target=''
site_path=''
site_report=''
site_status=0
site_url=''
site_php_version=''
site_php_state=''
site_raw_path=''

# Set by the checksum checks for check_modified_files(): whether core
# verified, and the slugs of wordpress.org plugins that verified.
core_verified=0
verified_plugins=''

# Result of each check for the current site, in the order run. Parallel
# arrays rather than an associative array, for Bash 3.2 on macOS.
check_keys=()
check_statuses=()

#######################################
# Prints usage information.
# Outputs:
#   Usage text to stdout.
#######################################
print_usage() {
	cat <<'USAGE'
Usage:
  wp-site-audit.sh --sites <file> --since <YYYY-MM-DD> [--site <label>] [--output <directory>]

Options:
  --sites    File listing the sites to audit.
  --since    Start of the exposure window. Files and accounts changed on or
             after this date are reported.
  --site     Audit only the site with this label.
  --output   Directory for the reports. Defaults to
             site-audit-<sites file name>[-<site>]-<timestamp>.

Sites file (one site per line, whitespace-separated, # starts a comment):
  <label> <ssh-target> <wordpress-path> [<log-file> ...]

  acme      deploy@203.0.113.10  /var/www/acme  /var/log/php8.3-fpm.log
  example   example-host         /home/example/public_html

Each server needs SSH key access and WP-CLI on the PATH.
USAGE
}

#######################################
# Parses and validates command-line arguments.
# Globals:
#   sites_file
#   since_date
#   output_directory
#   site_filter
# Arguments:
#   Command-line arguments.
# Outputs:
#   Errors to stderr. Exits on invalid input.
#######################################
parse_arguments() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
			--sites|--since|--site|--output)
				if [[ $# -lt 2 ]]; then
					echo "Missing value for $1" >&2
					exit 1
				fi
				case "$1" in
					--sites) sites_file="$2" ;;
					--since) since_date="$2" ;;
					--site) site_filter="$2" ;;
					--output) output_directory="$2" ;;
				esac
				shift 2
				;;
			-h|--help)
				print_usage
				exit 0
				;;
			*)
				echo "Unknown option: $1" >&2
				print_usage >&2
				exit 1
				;;
		esac
	done

	if [[ -z "$sites_file" || -z "$since_date" ]]; then
		print_usage >&2
		exit 1
	fi

	if [[ ! -r "$sites_file" ]]; then
		echo "Cannot read sites file: $sites_file" >&2
		exit 1
	fi

	if [[ ! "$since_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
		echo "Date must be in YYYY-MM-DD format: $since_date" >&2
		exit 1
	fi

	if [[ -z "$output_directory" ]]; then
		output_directory="$(default_output_directory)"
	fi
}

#######################################
# Builds the default report directory name from the sites file name, the
# --site label if given, and the current time, e.g.
# site-audit-dreamhost-20261023-1720 or
# site-audit-siteground-coreyrobin-20261023-1720.
#
# The file name is left out when the sites file is not a regular file, such
# as when it is passed with process substitution.
# Globals:
#   sites_file
#   site_filter
# Outputs:
#   Directory name to stdout.
#######################################
default_output_directory() {
	local sites_name=''
	local timestamp

	timestamp="$(date '+%Y%m%d-%H%M')"

	if [[ -f "$sites_file" ]]; then
		sites_name="$(basename "$sites_file")"
		sites_name="${sites_name%.*}"
	fi

	echo "site-audit-${sites_name:+${sites_name}-}${site_filter:+${site_filter}-}${timestamp}"
}

#######################################
# Runs a shell command on the current site's server.
#
# The command is sent base64-encoded and decoded on the server, because
# some SSH gateways (WP Engine's, for one) strip quotes and backslashes from
# the command they receive.
# Globals:
#   site_target
# Arguments:
#   Command to run remotely.
# Outputs:
#   Combined stdout and stderr of the remote command.
# Returns:
#   Exit status of the remote command.
#######################################
run_remote() {
	local command="$1"
	local encoded_command

	encoded_command="$(printf '%s' "$command" | base64 | tr -d '\n')"

	ssh -n -o BatchMode=yes -o ConnectTimeout=10 "$site_target" \
		"echo ${encoded_command} | base64 -d | bash" 2>&1
}

#######################################
# Runs a WP-CLI command in the current site's WordPress directory.
#
# Plugins and themes are not loaded, so compromised code in either cannot
# run during the audit.
# Globals:
#   site_path
# Arguments:
#   WP-CLI command and arguments.
# Outputs:
#   Combined stdout and stderr of the command.
# Returns:
#   Exit status of the command.
#######################################
run_wp() {
	run_remote "cd ${site_path} && wp --skip-plugins --skip-themes $*"
}

#######################################
# Appends a titled section to the current site report.
# Globals:
#   site_report
# Arguments:
#   Section title.
#   Section body.
#######################################
append_section() {
	local title="$1"
	local body="$2"

	{
		printf '\n## %s\n\n' "$title"
		printf '```\n%s\n```\n' "${body:-(none)}"
	} >> "$site_report"
}

#######################################
# Records a check's result and raises the current site's status if the
# result is more severe.
# Globals:
#   site_status
#   check_keys
#   check_statuses
# Arguments:
#   Status from the check.
#   Key identifying the check (see describe_check).
#######################################
record_status() {
	local status="$1"
	local check_key="$2"

	check_keys+=( "$check_key" )
	check_statuses+=( "$status" )

	if (( status > site_status )); then
		site_status="$status"
	fi
}

#######################################
# Prints the client-facing description of a check.
# Arguments:
#   Check key.
# Outputs:
#   Description to stdout, or nothing for checks left out of the client
#   report.
#######################################
describe_check() {
	case "$1" in
		core) echo 'WordPress core files match the official release' ;;
		plugins) echo 'Plugins from the WordPress plugin directory match their official releases' ;;
		modified) echo 'Files changed since the vulnerability was announced are accounted for' ;;
		wp-config) echo 'The site configuration file contains no unexpected code' ;;
		uploads) echo 'The media uploads folder contains no scripts' ;;
		prepend) echo 'No code is set to load ahead of every page' ;;
		admins) echo 'No new administrator accounts' ;;
		logs) echo 'Server error logs show no signs of attack attempts' ;;
	esac
}

#######################################
# Formats a YYYY-MM-DD date as "October 20, 2026".
#
# Tries GNU date first, then BSD date (macOS).
# Arguments:
#   Date in YYYY-MM-DD format.
# Outputs:
#   Formatted date to stdout, or the input unchanged if neither works.
#######################################
format_date() {
	local input="$1"

	date -d "$input" '+%B %-d, %Y' 2>/dev/null \
		|| date -j -f '%Y-%m-%d' "$input" '+%B %-d, %Y' 2>/dev/null \
		|| echo "$input"
}

#######################################
# Writes the draft client-facing report for the current site.
#
# Checks that passed are marked "No issues". Anything else is marked for
# review, and the summary is left for a person to write, since deciding
# whether a finding matters takes judgement.
# Globals:
#   site_url
#   site_status
#   since_date
#   check_keys
#   check_statuses
# Arguments:
#   Path of the client report.
#######################################
write_client_report() {
	local client_report="$1"
	local index
	local description
	local result

	{
		printf '# Security Review: %s\n\n' "${site_url#*://}"
		printf 'Reviewed: %s  \n' "$(date '+%B %-d, %Y')"
		printf 'Period checked: %s to the date of review\n\n' "$(format_date "$since_date")"
		printf 'On October 21, a serious security vulnerability in PHP, the software WordPress runs on, was made public. I reviewed the site to make sure it was not affected before the fix was in place.\n\n'
		printf '## What I Checked\n\n'
		printf '| Check | Result |\n'
		printf '| --- | --- |\n'

		for index in "${!check_keys[@]}"; do
			if [[ "${check_keys[$index]}" == 'php-patch' ]]; then
				description="PHP version: ${site_php_version:-unknown} (${site_php_state})"
			else
				description="$(describe_check "${check_keys[$index]}")"
			fi

			if [[ -z "$description" ]]; then
				continue
			fi

			if (( check_statuses[index] == STATUS_OK )); then
				result='No issues'
			else
				result='**[Review before sending]**'
			fi

			printf '| %s | %s |\n' "$description" "$result"
		done

		printf '\n## Summary\n\n'

		if (( site_status == STATUS_OK )); then
			printf 'I found no signs that the site was affected. No further action is needed.\n'
		else
			printf '**[Write the summary: what was found and what, if anything, needs to be done. Update the results above.]**\n'
		fi
	} > "$client_report"
}

#######################################
# Reports the PHP CLI and PHP-FPM versions installed on the server.
#
# Informational only: distribution packages often backport fixes without
# changing the upstream version number.
# Returns:
#   STATUS_OK.
#######################################
check_php_versions() {
	local output

	output="$(run_remote 'php -v 2>/dev/null | head -n 1; for binary in /usr/sbin/php-fpm* /usr/local/sbin/php-fpm; do [ -x "$binary" ] && echo "$binary: $("$binary" -v | head -n 1)"; done')"
	append_section 'PHP versions' "$output"

	return "$STATUS_OK"
}

#######################################
# Checks whether the server's command-line PHP includes the PHP2Shell fix.
#
# Fixed releases are 8.2.35, 8.3.36, 8.4.27 and 8.5.12. Branches after 8.5
# are treated as fixed. 8.1 and older have no official fix, so only a
# host's backport could have patched them, which the version number does
# not show.
# Globals:
#   site_php_version
#   site_php_state
# Returns:
#   STATUS_OK if patched, otherwise STATUS_REVIEW.
#######################################
check_php_patch() {
	local major
	local minor
	local patch
	local fixed_patch=''

	site_php_version="$(run_remote "php -r 'echo PHP_VERSION;'")"

	if [[ ! $site_php_version =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
		site_php_version=''
		site_php_state='Unknown'
		append_section 'PHP patch status' 'Could not read the PHP version.'
		return "$STATUS_REVIEW"
	fi

	major="${BASH_REMATCH[1]}"
	minor="${BASH_REMATCH[2]}"
	patch="${BASH_REMATCH[3]}"

	case "${major}.${minor}" in
		8.2) fixed_patch=35 ;;
		8.3) fixed_patch=36 ;;
		8.4) fixed_patch=27 ;;
		8.5) fixed_patch=12 ;;
	esac

	if [[ -n "$fixed_patch" ]]; then
		if (( patch >= fixed_patch )); then
			site_php_state='Patched'
		else
			site_php_state='Not patched'
		fi
	elif (( major > 8 || (major == 8 && minor > 5) )); then
		site_php_state='Patched'
	else
		site_php_state='Not confirmed'
	fi

	append_section 'PHP patch status' "${site_php_version}: ${site_php_state}"

	if [[ "$site_php_state" == 'Patched' ]]; then
		return "$STATUS_OK"
	fi

	return "$STATUS_REVIEW"
}

#######################################
# Verifies WordPress core files against the official checksums.
#
# Warnings matching IGNORED_CORE_WARNINGS still appear in the report but do
# not affect the status.
# Returns:
#   STATUS_FLAG if any other warning is reported, STATUS_REVIEW if
#   verification could not run, otherwise STATUS_OK.
#######################################
check_core_checksums() {
	local output
	local remaining_warnings

	output="$(run_wp core verify-checksums)"
	append_section 'Core checksums' "$output"

	remaining_warnings="$(grep '^Warning:' <<< "$output" | grep -vE "$IGNORED_CORE_WARNINGS")"

	if [[ -n "$remaining_warnings" ]]; then
		return "$STATUS_FLAG"
	fi

	if grep '^Error:' <<< "$output" | grep -qv "doesn't verify against checksums"; then
		return "$STATUS_REVIEW"
	fi

	core_verified=1

	return "$STATUS_OK"
}

#######################################
# Verifies wordpress.org plugins against the official checksums, and
# records which plugins verified for check_modified_files().
#
# A plugin counts as verified when it is installed, has no failing files,
# and was not skipped. Plugins not hosted on wordpress.org are skipped by
# WP-CLI; changes to them are caught by check_modified_files().
# Globals:
#   verified_plugins
# Returns:
#   STATUS_FLAG if any file was changed, added, or removed, otherwise
#   STATUS_OK.
#######################################
check_plugin_checksums() {
	local output
	local installed_plugins
	local unverified_plugins

	output="$(run_wp plugin verify-checksums --all)"
	append_section 'Plugin checksums' "$output"

	installed_plugins="$(run_wp plugin list --field=name | grep -E '^[A-Za-z0-9._-]+$' | sort -u)"
	unverified_plugins="$(
		{
			awk -F'\t' 'NF >= 3 && $1 != "plugin_name" { print $1 }' <<< "$output"
			grep -oE 'of plugin [^,]+, skipping' <<< "$output" | sed -E 's/^of plugin (.+), skipping$/\1/'
		} | sort -u
	)"

	# If verification failed outright, no plugin counts as verified.
	if grep -q '^Error:' <<< "$output" && ! grep -qE 'Only verified|plugin_name' <<< "$output"; then
		verified_plugins=''
	else
		verified_plugins="$(comm -23 <(echo "$installed_plugins") <(echo "$unverified_plugins"))"
	fi

	if grep -qE 'Checksum does not match|File was added|File is missing' <<< "$output"; then
		return "$STATUS_FLAG"
	fi

	return "$STATUS_OK"
}

#######################################
# Prints whether a file is covered by a checksum check that passed.
# Globals:
#   site_raw_path
#   core_verified
#   verified_plugins
# Arguments:
#   Absolute path of the file on the server.
# Returns:
#   0 if the file is in verified core or a verified plugin, otherwise 1.
#######################################
is_checksum_verified() {
	local relative_path="${1#"${site_raw_path%/}"/}"
	local plugin_slug

	if (( core_verified )); then
		if [[ $relative_path == wp-admin/* || $relative_path == wp-includes/* ]]; then
			return 0
		fi

		# Core files in the WordPress root. The slash check matters: in a
		# pattern, * also matches "/", so wp-*.php alone would match
		# everything under wp-content.
		if [[ $relative_path != */* && $relative_path != 'wp-config.php' ]] \
			&& [[ $relative_path == 'index.php' || $relative_path == 'xmlrpc.php' || $relative_path == wp-*.php ]]; then
			return 0
		fi
	fi

	if [[ $relative_path == wp-content/plugins/*/* ]]; then
		plugin_slug="${relative_path#wp-content/plugins/}"
		plugin_slug="${plugin_slug%%/*}"

		if grep -qxF "$plugin_slug" <<< "$verified_plugins"; then
			return 0
		fi
	fi

	return 1
}

#######################################
# Lists PHP and server configuration files modified since the start date.
#
# Files in core or in wordpress.org plugins that passed their checksum check
# are left out, since they are identical to the official release whatever
# their date. The number left out is noted in the report.
# Globals:
#   since_date
# Returns:
#   STATUS_REVIEW if any other files were modified, otherwise STATUS_OK.
#######################################
check_modified_files() {
	local output
	local line
	local file
	local findings=''
	local omitted_count=0

	output="$(run_remote "find ${site_path} -type f \\( -name '*.php' -o -name '.htaccess' -o -name '.user.ini' \\) -newermt ${since_date} -not -path '*/cache/*' -printf '%TY-%Tm-%Td %TH:%TM  %p\\n' | sort")"

	while IFS= read -r line; do
		if [[ -z "$line" ]]; then
			continue
		fi

		file="${line#*  }"

		if [[ $line == *'  /'* ]] && is_checksum_verified "$file"; then
			omitted_count=$(( omitted_count + 1 ))
			continue
		fi

		findings+="${line}"$'\n'
	done <<< "$output"

	append_section "Files modified since ${since_date}" "${findings%$'\n'}"

	if (( omitted_count > 0 )); then
		printf '\n%d file(s) in checksum-verified core and plugins left out.\n' "$omitted_count" >> "$site_report"
	fi

	if [[ -n "$findings" ]]; then
		return "$STATUS_REVIEW"
	fi

	return "$STATUS_OK"
}

#######################################
# Prints the paths of files whose content contains a line that is not
# allowed in a placeholder index.php.
# Arguments:
#   Output of grep -H '' for the candidate files ("path:line" per line).
# Outputs:
#   Unique file paths to stdout.
#######################################
list_non_placeholder_files() {
	local contents="$1"
	local line
	local file
	local text

	while IFS= read -r line; do
		if [[ -z "$line" ]]; then
			continue
		fi

		file="${line%%:*}"
		text="${line#*:}"

		if [[ ! $text =~ $PLACEHOLDER_LINE_PATTERN ]]; then
			echo "$file"
		fi
	done <<< "$contents" | sort -u
}

#######################################
# Inspects wp-config.php if it was modified since the start date.
#
# Looks in the WordPress directory first, then one level up, where
# WordPress also allows it. Lines with code-execution or obfuscation
# functions, includes, and the WP_CACHE setting are reported.
# Globals:
#   since_date
# Returns:
#   STATUS_FLAG if an execution or obfuscation function is called,
#   STATUS_REVIEW if a file other than wp-settings.php is included,
#   otherwise STATUS_OK.
#######################################
check_wp_config() {
	local output
	local matches

	output="$(run_remote "file=${site_path}/wp-config.php; [ -f \"\$file\" ] || file=${site_path}/../wp-config.php; if [ -f \"\$file\" ] && [ -n \"\$(find \"\$file\" -newermt ${since_date})\" ]; then echo \"Modified: \$(date -r \"\$file\" '+%Y-%m-%d %H:%M')  \$file\"; grep -nE 'eval|base64_decode|gzinflate|str_rot13|assert|include|require|WP_CACHE' \"\$file\"; fi")"

	if [[ -z "$output" ]]; then
		append_section 'wp-config.php' "Not modified since ${since_date}"
		return "$STATUS_OK"
	fi

	append_section 'wp-config.php' "$output"
	matches="$(tail -n +2 <<< "$output")"

	if grep -qE '(eval|base64_decode|gzinflate|str_rot13|assert)[[:space:]]*\(' <<< "$matches"; then
		return "$STATUS_FLAG"
	fi

	if grep -E 'include|require' <<< "$matches" | grep -qv 'wp-settings\.php'; then
		return "$STATUS_REVIEW"
	fi

	return "$STATUS_OK"
}

#######################################
# Prints the site's uploads directory as WordPress resolves it.
#
# Covers the upload_path option and the UPLOADS constant. A directory set by
# a plugin filter is not seen, since plugins are not loaded.
# Outputs:
#   Absolute path of the uploads directory to stdout, or nothing if it
#   could not be determined.
#######################################
get_uploads_directory() {
	local uploads_directory

	uploads_directory="$(run_remote "cd ${site_path} && wp --skip-plugins --skip-themes eval 'echo wp_upload_dir()[\"basedir\"];'")"

	if [[ $uploads_directory == /* && $uploads_directory != *$'\n'* ]]; then
		echo "$uploads_directory"
	fi
}

#######################################
# Lists executable PHP files inside uploads directories.
#
# Searches any directory named uploads within the site, plus the uploads
# directory WordPress is configured to use, if it is elsewhere.
# Placeholder index.php files (see PLACEHOLDER_LINE_PATTERN) are counted in
# the report but not listed or flagged.
# Returns:
#   STATUS_FLAG if any other script is found, otherwise STATUS_OK.
#######################################
check_upload_scripts() {
	local uploads_directory
	local configured_root=''
	local listing
	local contents
	local suspicious_index_files
	local line
	local size
	local file
	local findings=''
	local ignored_count=0

	uploads_directory="$(get_uploads_directory)"

	if [[ -n "$uploads_directory" ]]; then
		configured_root="$(printf '%q' "$uploads_directory")"
	fi

	listing="$(run_remote "{ find ${site_path} -type f -path '*/uploads/*' \\( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \\) -printf '%s\\t%p\\n'; ${configured_root:+find ${configured_root} -type f \\( -iname '*.php' -o -iname '*.php[0-9]' -o -iname '*.phtml' -o -iname '*.phar' \\) -printf '%s\\t%p\\n';} } | sort -u")"
	contents="$(run_remote "{ find ${site_path} -type f -path '*/uploads/*' -name index.php -size -$(( PLACEHOLDER_MAX_BYTES + 1 ))c -exec grep -H '' {} +; ${configured_root:+find ${configured_root} -type f -name index.php -size -$(( PLACEHOLDER_MAX_BYTES + 1 ))c -exec grep -H '' {} +;} } | sort -u")"
	suspicious_index_files="$(list_non_placeholder_files "$contents")"

	while IFS= read -r line; do
		if [[ -z "$line" ]]; then
			continue
		fi

		# Lines without a tab are errors from find; report them as they are.
		if [[ $line != *$'\t'* ]]; then
			findings+="${line}"$'\n'
			continue
		fi

		size="${line%%$'\t'*}"
		file="${line#*$'\t'}"

		if [[ ${file##*/} == 'index.php' ]] \
			&& (( size <= PLACEHOLDER_MAX_BYTES )) \
			&& ! grep -qxF "$file" <<< "$suspicious_index_files"; then
			ignored_count=$(( ignored_count + 1 ))
			continue
		fi

		findings+="${size} bytes  ${file}"$'\n'
	done <<< "$listing"

	append_section "Scripts in uploads (configured directory: ${uploads_directory:-unknown})" "${findings%$'\n'}"

	if (( ignored_count > 0 )); then
		printf '\n%d placeholder index.php file(s) ignored.\n' "$ignored_count" >> "$site_report"
	fi

	if [[ -n "$findings" ]]; then
		return "$STATUS_FLAG"
	fi

	return "$STATUS_OK"
}

#######################################
# Finds auto_prepend_file and auto_append_file directives, which can load
# code before or after every request.
# Returns:
#   STATUS_REVIEW if any are found, otherwise STATUS_OK.
#######################################
check_prepend_directives() {
	local output

	output="$(run_remote "grep -rIn --include='.user.ini' --include='.htaccess' --include='php.ini' -e auto_prepend_file -e auto_append_file ${site_path}")"
	append_section 'Prepend and append directives' "$output"

	if [[ -n "$output" ]]; then
		return "$STATUS_REVIEW"
	fi

	return "$STATUS_OK"
}

#######################################
# Lists administrators and flags any registered since the start date.
#
# WP-CLI quotes CSV fields that contain spaces, so the quotes are stripped
# from the registration date before comparing it.
# Globals:
#   since_date
# Returns:
#   STATUS_FLAG if a new administrator exists, STATUS_REVIEW if the list
#   could not be retrieved, otherwise STATUS_OK.
#######################################
check_administrators() {
	local output
	local exit_code
	local new_administrators

	output="$(run_wp user list --role=administrator --fields=user_login,user_email,user_registered --format=csv)"
	exit_code=$?
	append_section 'Administrators' "$output"

	if (( exit_code != 0 )); then
		return "$STATUS_REVIEW"
	fi

	new_administrators="$(awk -F, -v since="$since_date" 'NR > 1 { registered = $NF; gsub(/"/, "", registered); if (registered >= since) print }' <<< "$output")"

	if [[ -n "$new_administrators" ]]; then
		append_section "Administrators registered since ${since_date}" "$new_administrators"
		return "$STATUS_FLAG"
	fi

	return "$STATUS_OK"
}

#######################################
# Lists scheduled WP-Cron events for manual review.
# Returns:
#   STATUS_OK.
#######################################
check_cron_events() {
	local output

	output="$(run_wp cron event list --fields=hook,next_run_relative,recurrence --format=table)"
	append_section 'Cron events' "$output"

	return "$STATUS_OK"
}

#######################################
# Searches server logs for PHP worker crashes and memory exhaustion, which
# exploitation attempts against memory corruption flaws tend to leave behind.
# Arguments:
#   Log file paths on the server. None means the check is skipped.
# Returns:
#   STATUS_REVIEW if any matches are found, otherwise STATUS_OK.
#######################################
check_logs() {
	local log_file
	local output
	local result="$STATUS_OK"

	for log_file in "$@"; do
		output="$(run_remote "grep -E 'signal (6|11)|SIGSEGV|SIGBUS|Allowed memory size of' $(printf '%q' "$log_file") | tail -n 25")"
		append_section "Log: ${log_file}" "$output"

		if [[ -n "$output" ]]; then
			result="$STATUS_REVIEW"
		fi
	done

	return "$result"
}

#######################################
# Runs every check against one site and writes its report.
# Globals:
#   site_target
#   site_path
#   site_report
#   site_status
#   output_directory
#   since_date
# Arguments:
#   Site label.
#   SSH target.
#   WordPress path on the server.
#   Optional log file paths.
# Outputs:
#   Summary line to stdout.
#######################################
audit_site() {
	local label="$1"
	local target="$2"
	local path="$3"
	local connection_output
	shift 3

	site_target="$target"
	site_path="$(printf '%q' "$path")"
	site_report="${output_directory}/${label}.md"
	site_status="$STATUS_OK"
	site_url="$label"
	site_php_version=''
	site_php_state=''
	site_raw_path="$path"
	core_verified=0
	verified_plugins=''
	check_keys=()
	check_statuses=()

	printf '# %s\n\nTarget: %s:%s  \nSince: %s  \nRun: %s\n' \
		"$label" "$target" "$path" "$since_date" "$(date '+%Y-%m-%d %H:%M')" > "$site_report"

	if ! connection_output="$(run_wp core version)"; then
		append_section 'Connection' "$connection_output"
		site_status="$STATUS_ERROR"
	else
		site_url="$(run_wp option get home)" || site_url="$label"

		check_php_patch
		record_status $? 'php-patch'
		check_php_versions
		record_status $? 'php'
		check_core_checksums
		record_status $? 'core'
		check_plugin_checksums
		record_status $? 'plugins'
		check_modified_files
		record_status $? 'modified'
		check_wp_config
		record_status $? 'wp-config'
		check_upload_scripts
		record_status $? 'uploads'
		check_prepend_directives
		record_status $? 'prepend'
		check_administrators
		record_status $? 'admins'
		check_cron_events
		record_status $? 'cron'

		if (( $# > 0 )); then
			check_logs "$@"
			record_status $? 'logs'
		fi

		write_client_report "${output_directory}/${label}-client.md"
	fi

	printf '%-7s %-24s %s\n' "${STATUS_LABELS[$site_status]}" "$label" "$site_report"
}

#######################################
# Audits every site listed in the sites file, or only the one named by
# --site.
# Globals:
#   sites_file
#   output_directory
#   site_filter
# Arguments:
#   Command-line arguments.
# Outputs:
#   Per-site summary to stdout and to summary.txt in the output directory.
#######################################
main() {
	local -a fields

	parse_arguments "$@"
	mkdir -p "$output_directory"

	# The second condition keeps the last line when the file has no trailing
	# newline.
	while read -r -a fields || (( ${#fields[@]} > 0 )); do
		if [[ ${#fields[@]} -eq 0 || ${fields[0]} == \#* ]]; then
			continue
		fi

		if (( ${#fields[@]} < 3 )); then
			echo "Skipping incomplete line: ${fields[*]}" >&2
			continue
		fi

		if [[ -n "$site_filter" && ${fields[0]} != "$site_filter" ]]; then
			continue
		fi

		audit_site "${fields[@]}"
	done < "$sites_file" | tee "${output_directory}/summary.txt"
}

main "$@"
