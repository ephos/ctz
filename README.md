# ctz

`ctz` is a Go rewrite of `connectivity-test-zone.sh`. It enumerates DNS
subdomains for one or more zones, resolves each hostname, scans selected TCP
ports with `nmap`, collects TLS certificate metadata, and emits the same
JSON-first results (schema version 2.0) for authorized asset inventory and
security assessment evidence collection. It adds an interactive terminal UI.

Use only for authorized security testing, asset inventory, and network
administration. See [../DISCLAIMER.md](../DISCLAIMER.md).

## Build

```console
cd ctz
go build -o ctz .
```

## Dependencies

Everything the original script did in Python is built in. These external tools
are still executed when the matching feature is used: `subfinder` and `nmap`
(always), `dnsx` (`--wordlist`), `gobuster` (`--vhosts`), `wafw00f` (`--waf`),
`whois` (`--whois`), `nuclei` (`--nuclei`), and `docker` (`--zap`). See the
[top-level README](../README.md) for installation.

## CLI

```console
ctz scan --domain example.com [options]
ctz --domain example.com [options]        # same as `ctz scan`
ctz tui                                    # interactive UI
```

All options of the original script are supported with the same long names and
defaults (`ctz scan -h` lists them). The original multi-letter short options
(`-df -wl -vh -vwl -vs -vu -wf -ii -wi -sv -he -nu -zap -oj -od`) are accepted
too; `-d`, `-r`, `-p` and `-h` are native shorthands.

```console
ctz -d example.com
ctz -d example.com -wl default             # embedded DNS wordlist
ctz -df domains.txt -wl wordlist.txt -oj
ctz -d example.com -oj -sv -he -nu -zap
ctz -d example.com -p 22,80,443 -oj -od ./results
```

Differences from the script:

- Progress goes to stderr and JSON to stdout, as before, but console JSON is
  colorized only when stdout is a terminal (piping gives plain JSON).
- The default vhost wordlist and a 1,200-entry DNS brute-force wordlist are
  embedded in the binary. `--wordlist default` (`-wl default`) selects the
  embedded DNS list; any other value is read as a file path. DNS brute-forcing
  still runs only when `--wordlist` is given, as in the script, and needs
  `dnsx`.
- `--ports` is validated up front.
- Ctrl-C cancels the scan cleanly.
- nmap runs in two phases. A fast port-discovery pass (no `-sV`, no NSE) runs
  first, then service detection and NSE run against only the open ports, with
  `--script-timeout 30s`. A stalled detail scan therefore can't wipe out the
  basic results, which the script's single combined run can when it hits the
  per-host timeout.
- If nmap finds no open ports (or fails), a plain TCP connect probe of the same
  ports runs as a fallback so TLS and HTTP evidence are still collected.
- Scan failures are reported instead of dropped. A target gets an optional
  `scan_errors` array (omitted when empty) describing nmap errors, timeouts,
  unparseable output, or ports the fallback found that nmap missed. This is the
  only field not in the script's schema.
- As in the script, setting a dependent option implies its feature
  (`--vhost-wordlist`/`--vhost-url` → `--vhosts`, `--nse-scripts` → `--nse`,
  `--nuclei-severities`/`--nuclei-templates` → `--nuclei`, any `--zap-*` →
  `--zap`).

## TUI

`ctz tui` opens a three-stage interface built with Bubble Tea and Lip Gloss:

1. **Form** – every option of the CLI, with defaults filled in (below).
2. **Progress** – spinner, progress bar and live log (`esc` cancels; `tab`
   browses targets that have already finished).
3. **Results** – browse targets, with Summary / Overview / TLS / HTTP / Hints tabs.

### Form

Move with `↑/↓`, toggle with `space`/`enter`, `ctrl+a` turns every scan option
on or off, and `ctrl+r` runs. The form scrolls to keep the selected row in view
on short terminals.

Each toggle has its settings underneath it: NSE script set; vhost wordlist,
scheme and base URL; nuclei severities and templates; ZAP image, spider
minutes, timeout and max endpoints. Editing one of these turns its toggle on
(the same implication the CLI applies), so what you see is what runs.

Defaults:

| Option | Default |
| --- | --- |
| Service versions, HTTP evidence, Save JSON | on |
| WAF detection | on if `wafw00f` is installed |
| Registration (RDAP/whois) | on if `whois` is installed |
| DNS wordlist | `default` (embedded list, enables `dnsx` brute-force) if `dnsx` is installed, else empty |
| ipinfo.io | on if `$IPINFO_API_KEY` is set |
| NSE scripts, Nuclei, ZAP, Vhost enumeration | off |

Options that need an extra tool start off unless the tool is present, so a
default run never stops on a missing dependency. NSE stays off because it is the
slowest option.

### Results

| Key | Action |
| --- | --- |
| `↑/↓` or `j/k` | select target |
| `←/→`, `h/l`, `1`–`5` | switch tab |
| `pgup/pgdn` | scroll the detail pane |
| `[` / `]` | narrow / widen the target list |
| `s` | save JSON |
| `n` | new scan |
| `d` | dependency check |
| `q` | quit |

Long target names are truncated with `…` rather than wrapped; widen the list
with `]` to see more.

The first tab, **Summary**, is an at-a-glance view for the selected target. It
exists only in the TUI and is not part of the JSON output. From top to bottom:

- a badge row: connected or not, certificate state (valid / needs attention /
  expired), WAF, the PHP banner version (red if flagged for the tracked CVEs),
  and finding counts by severity
- **Open ports** as chips; ports flagged by the exposure hints (RDP, SMB,
  databases and so on) are coloured amber or red
- **TLS** per certificate: subject, issuer, a lifetime gauge with days left or
  days since expiry, whether the certificate covers the hostname (wildcards
  count for one label), and a self-signed marker
- **Web & technology**: server and `X-Powered-By` banners (merged with nmap's
  product/version), PHP status, WAF, and for each HTTP endpoint its status,
  title, redirect target and a security-header score gauge
- **Findings**: the top prioritization hints for the target, scan issues, and
  how many NSE scripts errored

Card borders turn amber or red when something in them needs attention. The
Summary only repeats data already collected, so sections for features that
were not run show "not checked" or "none identified" rather than a result.

The Overview tab shows a `PHP` line whenever HTTP evidence ran: the version from the
`Server` / `X-Powered-By` banner and whether it falls in the range flagged for
CVE-2026-109618 and CVE-2026-109619, or "version not disclosed". This is
banner-only triage. Banners can be stale, spoofed or backported, and many
hardened or CDN-fronted servers don't disclose a version, so a hit needs
confirming against the installed package and the vendor advisory.

### Dependency check

The TUI checks for the external tools on startup and opens a popup if
`subfinder` or `nmap` is missing. `ctrl+d` (or `d` on the results screen) reopens
it at any time; it updates live as you toggle options.

- green – found on `PATH`
- red – missing and needed by the selected options (blocks Run)
- yellow – missing but optional for the current options

Below the list it shows install commands for the missing tools for `apt`, `dnf`
and `pacman` (your distribution's is marked `▸`), plus `go install` /
`pipx` lines for tools that aren't packaged. The CLI prints the same hint when
it exits for missing dependencies.

## Troubleshooting

**`ERROR: Script execution failed (use -d to debug)` on NSE scripts.** These
come from nmap, not ctz; ctz stores each script's output as nmap reports it.
They show in the TUI as maroon italics with a hint and a command to reproduce
the run with debug output. With nmap 7.992 (built against Lua 5.4, running
with Lua 5.5 installed) the scripts that call `nmap.version_intensity()` in
their port rule (`http-server-header`, `https-redirect`, `hnap-info`,
`rpcinfo`, `vmware-version` and others, 13 in all) throw `attempt to index a
nil value` during a full `default,safe` run. They do not fail when run alone,
and the original script's nmap arguments produce the same errors. The cause is
not confirmed, so treat it as a likely nmap or packaging problem rather than a
target problem. The other script results in the same run are valid.

**Empty ports/TLS for a host that is clearly up.** Check the target's
`scan_errors`. A combined `-sV` + NSE scan can exceed nmap's per-host timeout,
in which case nmap reports nothing for the host; ctz's two-phase scan and
connect-probe fallback exist for this.

## Development

```console
go vet ./...
go test ./...
```

Tests need no network or external tools; commands are faked through
`internal/execx.Runner`.

## Layout

| Path | Purpose |
| --- | --- |
| `cmd/` | cobra commands (`scan`, `tui`) |
| `internal/runner` | scan pipeline; emits progress events used by CLI and TUI |
| `internal/enum` | subfinder / dnsx / gobuster enumeration |
| `internal/scan` | DNS resolution and nmap |
| `internal/tlsinfo`, `httpev`, `waf`, `nuclei`, `zap` | evidence collectors |
| `internal/registration`, `ipinfo` | RDAP/whois and ipinfo.io lookups |
| `internal/hints` | prioritization hints |
| `internal/model`, `report` | JSON schema types, output and colorizer |
| `internal/tui` | Bubble Tea UI |
