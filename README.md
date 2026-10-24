# wp-site-audit.sh

Audits WordPress sites over SSH for signs of compromise since a given date. It was written for the PHP2Shell vulnerabilities (CVE-2026-109618 and CVE-2026-109619), but nothing in it is specific to them: the date is an argument, so it works for any incident with a known start.

The script only reads. Nothing on the servers is changed, and WP-CLI runs with `--skip-plugins --skip-themes`, so compromised plugin or theme code can't run during the audit.

## Requirements

**Local**

- Bash 3.2 or later (the macOS default is fine)
- SSH key access to each site

**Server**

- WP-CLI on the `PATH`
- GNU `find` (for `-printf` and `-newermt`), `grep` and `base64`

Standard Linux hosts have all of these. SiteGround, WP Engine and DreamHost all work.

## Usage

```
./wp-site-audit.sh --sites <file> --since <YYYY-MM-DD> [--site <label>] [--output <directory>]
```

| Option | Description |
| --- | --- |
| `--sites` | File listing the sites to audit |
| `--since` | Start of the exposure window. Files and accounts changed on or after this date are reported |
| `--site` | Audit only the site with this label |
| `--output` | Directory for the reports. Defaults to `site-audit-<sites file name>[-<site>]-<timestamp>` |

Examples:

```
./wp-site-audit.sh --sites siteground.txt --since 2026-10-20
./wp-site-audit.sh --sites siteground.txt --since 2026-10-20 --site example-com
```

## Sites File

One site per line, fields separated by whitespace:

```
<label>  <ssh-target>  <wordpress-path>  [<log-file> ...]
```

- **label**: used for the report file names and `--site`
- **ssh-target**: anything `ssh` accepts: `user@host` or a host alias from `~/.ssh/config`
- **wordpress-path**: absolute path to the WordPress directory on the server. Use a full path; `~` is not expanded
- **log-file**: optional. Server error logs to search for PHP crashes and memory errors

Lines starting with `#` and blank lines are skipped.

```
# Clients
example-com   sg-example       /home/customer/www/example.com/public_html
example-org   dh-example       /home/example/example.org  /home/example/logs/example.org/https/error.log
```

## Output

Each run writes a directory containing:

| File | Contents |
| --- | --- |
| `<label>.md` | Technical report: the full output of every check |
| `<label>-client.md` | Draft report for the client, in plain language |
| `summary.txt` | One status line per site, also printed to the terminal |

Sites that couldn't be reached get a technical report with the connection error and no client report.

## Statuses

| Status | Meaning |
| --- | --- |
| `OK` | Nothing found |
| `REVIEW` | Something changed or is unusual, and needs a look |
| `FLAG` | Something that could indicate compromise |
| `ERROR` | Couldn't connect, or WP-CLI didn't run |

A site's status is the most severe result of any of its checks.

## Checks

| Check | Window only | Raises |
| --- | --- | --- |
| PHP patch status | No | `REVIEW` if below the fixed release for its branch, or 8.1 and older |
| PHP versions installed | No | Information only |
| Core checksums | No | `FLAG` on modified, missing or extra core files; `REVIEW` if verification couldn't run |
| Plugin checksums | No | `FLAG` on modified, added or missing files in wordpress.org plugins |
| Modified files | Yes | `REVIEW` on PHP, `.htaccess` and `.user.ini` files changed since `--since` |
| `wp-config.php` | Yes | `FLAG` on `eval(`, `base64_decode(`, `gzinflate(`, `str_rot13(` or `assert(`; `REVIEW` on includes other than `wp-settings.php` |
| Scripts in uploads | No | `FLAG` on any PHP file in an uploads directory |
| Prepend directives | No | `REVIEW` on `auto_prepend_file` or `auto_append_file` |
| Administrators | Yes | `FLAG` on admins registered since `--since` |
| Cron events | No | Information only |
| Logs | No | `REVIEW` on segfaults and memory exhaustion, when log files are given |

"Window only" means the check looks only at changes since `--since`. The others report what they find whatever its age, so on older sites they will turn up problems that predate the incident. Check a file's date to tell which side of the window it's on.

### Known-Harmless Results

These are set at the top of the script and can be extended:

- **`IGNORED_CORE_WARNINGS`**: core checksum warnings that don't affect the status. Currently `php_errorlog` files in core directories, `wp-includes/.htaccess`, and missing `readme.html`, `license.txt` and `wp-config-sample.php`. They still appear in the technical report.
- **Placeholder `index.php` files** in uploads, the "Silence is golden" kind, are counted but not flagged. A file qualifies if it is 200 bytes or less and contains only blank lines, PHP open and close tags, and `//` or `#` comments without a `?`.

### Uploads Directories

The uploads check searches every directory named `uploads` in the site, plus the directory WordPress reports through `wp_upload_dir()`. That covers a custom directory set with the `upload_path` option or the `UPLOADS` constant. A directory set by a plugin filter isn't seen, since plugins aren't loaded.

## Client Report

`<label>-client.md` lists each check in plain language with "No issues" or **[Review before sending]**. If everything passed, the summary says no further action is needed. Otherwise it's a placeholder: deciding whether a finding matters takes judgement, so the summary is yours to write.

The PHP row shows the command-line PHP version. On hosts that run several versions side by side, it may not be the version serving the site; correct it by hand if so.

## Host Notes

Keep each host's SSH settings in its own file and include them at the top of `~/.ssh/config`, above any `Host` block:

```
Include ~/.ssh/config.d/config.siteground
Include ~/.ssh/config.d/config.dreamhost
Include ~/.ssh/config.d/config.wpengine
```

The script runs SSH in batch mode, so host keys must be accepted ahead of time or with `StrictHostKeyChecking accept-new`.

### SiteGround

- Port 18765; each site has its own SSH user, shown in Site Tools under Devs → SSH Keys Manager
- Use `ssh.<domain>` as the host name. It reaches the server even when the site is behind SiteGround's CDN or Cloudflare
- WordPress lives at `/home/customer/www/<domain>/public_html`
- Logs aren't available over SSH

```
Host sg-example
    HostName ssh.example.com
    User u0000-xxxxxxxxxxxx

Host sg-*
    Port 18765
    StrictHostKeyChecking accept-new
```

### DreamHost

- Standard port 22
- WordPress lives at `/home/<user>/<domain>`
- Logs are at `/home/<user>/logs/<domain>/https/error.log` and `.../http/error.log`
- If the panel doesn't deploy your key to a user, copy it yourself with `ssh-copy-id -i ~/.ssh/<key>.pub <user>@<host>`

### WP Engine

- Each environment is its own install. The SSH user is the install name and the host is `<install>.ssh.wpengine.net`
- WordPress lives at `/sites/<install>`
- Logs aren't available over SSH
- The gateway takes about 20 seconds per command, so one install takes around 5 minutes. Run installs in parallel:

```
for site in $(awk '!/^#/ && NF { print $1 }' wpengine.txt); do
	./wp-site-audit.sh --sites wpengine.txt --site "$site" --since 2026-10-20 &
done
wait
```

The gateway also strips quotes and backslashes from commands. The script works around this by sending every command base64-encoded and decoding it on the server.

## Reinstalling Flagged Plugins

When the plugin checksum check flags wordpress.org plugins, this reinstalls each of them from wordpress.org at the version already installed. Run it on the server, from the WordPress directory:

```
wp plugin verify-checksums --all --format=csv 2>/dev/null \
	| awk -F, 'NR > 1 { print $1 }' | sort -u \
	| while read -r plugin; do
		wp plugin install "$plugin" --force --version="$(wp plugin get "$plugin" --field=version)"
	done
```

- The first line lists only plugins with mismatches. Warnings about premium plugins, which have no published checksums, are discarded
- `awk` and `sort -u` reduce the list to one slug per plugin
- `--version` keeps the installed version. Leave it out to update each plugin to the latest version instead

A reinstall overwrites the plugin's files but doesn't delete files that aren't part of it. Run the audit again afterwards: the reinstalled plugins will show up in the modified-files check with the current date, and their checksums should now pass.

## Limitations

- Premium and custom plugins have no published checksums. Changes to them only show up in the modified-files check
- Code-execution checks rely on file contents and dates. An attacker who sets a file's date back won't show up in the modified-files check
- The PHP version is the command-line version, not necessarily the one serving the site
