#!/usr/bin/env bash
# Build (if needed) and launch the pentest TUI.
set -e
cd "$(dirname "$0")"

# Go toolchain first, so the `go build` below is found. This repo was set up
# with Go installed to ~/go-sdk/go; only prepend that if it exists, otherwise
# fall back to whatever `go` is already on PATH.
if [ -x "$HOME/go-sdk/go/bin/go" ]; then
	export PATH="$HOME/go-sdk/go/bin:$PATH"
fi

if ! command -v go >/dev/null 2>&1; then
	echo "run.sh: 'go' not found on PATH." >&2
	echo "Install Go 1.27+ (or put it at ~/go-sdk/go) and try again." >&2
	exit 1
fi

# Pure-Go build: the --web server pulls in net/http, and the system gcc here
# crashes on cgo, so keep cgo off (the DNS resolver falls back to pure Go).
export CGO_ENABLED=0
go build -o web .

# Put Go-installed tools on PATH so the commands assembled in the TUI and run
# with ctrl+r (or the browser's Run button under --web) can actually find their
# binaries. Most of the catalog
# (subfinder, dnsx, httpx, naabu, katana, gau, waybackurls, ffuf, gobuster,
# nuclei, dalfox, subzy, gowitness, amass, …) is installed with `go install`,
# which drops binaries in $GOBIN or $GOPATH/bin — neither of which is on the
# default PATH. The TUI shells out via `sh -c`, inheriting this PATH, so
# without this they come back "command not found".
gobin="$(go env GOBIN 2>/dev/null)"
if [ -z "$gobin" ]; then
	gopath="$(go env GOPATH 2>/dev/null)"
	[ -n "$gopath" ] && gobin="$gopath/bin"
fi
[ -n "$gobin" ] && export PATH="$gobin:$PATH"

# System pentest tools (sqlmap, nikto, …) sometimes live in sbin / local dirs,
# and the AD-mode tools (netexec, impacket-*, certipy, bloodhound-python, …) are
# usually pipx/pip installs under ~/.local/bin.
export PATH="$PATH:$HOME/.local/bin:/usr/local/bin:/usr/local/sbin:/usr/sbin:/sbin"

# Optional: point ffuf/gobuster at a system SecLists install instead of the
# bundled ./wordlists dir. Uncomment and adjust if you keep SecLists elsewhere.
# export PENTEST_TUI_WORDLISTS="$HOME/tools/SecLists"

exec ./web "$@"
