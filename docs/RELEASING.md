# Local releases

GitHub Actions is currently unavailable. Build and check the release locally
from the reviewed release commit. The commands below use PowerShell on Windows
11, Go from `C:\Program Files\Go\bin`, and `tar` (included with Windows or Git).
Use the patched Go version in `go.mod`; automatic toolchain downloads must be
enabled. No external Go modules or C compiler are needed to build the binaries.

## Local gate

Run from the repository root:

With GNU Make and a POSIX shell, install the check tools below, then run
`make check` and `make fuzz`. The single CI workflow mirrors these commands.
`make test` enables the race detector only when cgo is enabled. On Windows,
Git Bash supplies the shell; GNU Make must also be on PATH.

The equivalent PowerShell gate without a C compiler is:

```powershell
$ErrorActionPreference = 'Stop'
$env:PATH = 'C:\Program Files\Go\bin;' + $env:PATH
$env:GOTOOLCHAIN = 'auto'
$env:CGO_ENABLED = '0'
go version
$env:GOTOOLCHAIN = go env GOVERSION
go install golang.org/x/vuln/cmd/govulncheck@latest
if ($LASTEXITCODE) { throw 'govulncheck installation failed' }
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0
if ($LASTEXITCODE) { throw 'golangci-lint installation failed' }
$toolBin = go env GOBIN
if (-not $toolBin) { $toolBin = Join-Path (go env GOPATH) 'bin' }
$env:PATH = "$toolBin;" + $env:PATH
$unformatted = gofmt -l ./cmd ./internal ./test
if ($LASTEXITCODE -or $unformatted) { throw "gofmt needed: $unformatted" }
go vet ./...
if ($LASTEXITCODE) { throw 'vet failed' }
golangci-lint run --enable-only staticcheck
if ($LASTEXITCODE) { throw 'staticcheck failed' }
golangci-lint run --concurrency=2
if ($LASTEXITCODE) { throw 'lint failed' }
go test -count=1 ./...
if ($LASTEXITCODE) { throw 'tests failed' }
govulncheck ./...
if ($LASTEXITCODE) { throw 'vulnerability check failed' }
```

`.gitattributes` keeps source, templates and golden fixtures at LF on Windows.
If an older checkout has CRLF files, run `gofmt -w ./cmd ./internal ./test` and
normalise the fixtures to LF before comparing generated output.

Run each fuzz target separately for 30 seconds. Generated coverage inputs stay
in the Go build cache; commit only a small regression input if a failure needs
one.

```powershell
foreach ($package in @('config', 'openai', 'proxy', 'evidence', 'archive', 'report', 'pdf')) {
    $names = go test "./internal/$package" -list '^Fuzz'
    if ($LASTEXITCODE) { throw "listing fuzz targets failed: $package" }
    foreach ($name in ($names | Where-Object { $_ -match '^Fuzz\w+$' })) {
        go test "./internal/$package" -run '^$' -fuzz "^${name}$" -fuzztime=30s -parallel=2 -timeout=2m
        if ($LASTEXITCODE) { throw "fuzzing failed: $package/$name" }
    }
}
```

The race gate is `CGO_ENABLED=1 go test -race -count=1 ./...` in a POSIX shell
with a C compiler, normally on Linux. It cannot run on Windows without a
compatible C toolchain. Unix permission tests skip on Windows because `os.Chmod`
does not enforce those permissions there; run them on Linux as a non-root user.
The broken-symlink archive test also skips on Windows. The reference verifier
needs `python3` and otherwise skips. Container and Helm checks need their
respective tools and are separate from the Go gate.

The fixed 5 ms proxy latency budget is checked on Linux with `make overhead`
and skips on Windows, where host scheduling makes it unreliable. Run this
measurement on an otherwise idle Linux host. Functional proxy and acceptance
tests still run on Windows.

## Build and checksum

`make build` builds both binaries for the host with version ldflags and needs
Make plus a POSIX shell. To checksum that local host build:

```bash
make build
(cd dist && sha256sum flugschreiber* proxyd* > SHA256SUMS)
(cd dist && sha256sum -c SHA256SUMS)
```

For distribution, this PowerShell script cross-compiles and packages Linux and
macOS on amd64/arm64 plus Windows on amd64, then writes `SHA256SUMS`:

```powershell
$version = 'v0.7.1' # Set to the patch release being prepared.
$env:CGO_ENABLED = '0'
$commit = git rev-parse HEAD
if ($LASTEXITCODE) { throw 'cannot identify the release commit' }
$buildDate = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$pkg = 'github.com/RamazanKara/flugschreiber/internal/version'
$ldflags = "-s -w -X $pkg.Version=$version -X $pkg.Commit=$commit -X $pkg.Date=$buildDate"
$releaseDir = Join-Path (Get-Location) "dist/$version"
New-Item -ItemType Directory -Path $releaseDir -ErrorAction Stop | Out-Null
$artifacts = @()
$oldGOOS, $oldGOARCH = $env:GOOS, $env:GOARCH
try {
    foreach ($target in @('linux/amd64', 'linux/arm64', 'darwin/amd64', 'darwin/arm64', 'windows/amd64')) {
        $env:GOOS, $env:GOARCH = $target.Split('/')
        $name = "flugschreiber_$($env:GOOS)_$($env:GOARCH)"
        $targetDir = Join-Path $releaseDir $name
        New-Item -ItemType Directory -Path $targetDir | Out-Null
        go build -trimpath "-ldflags=$ldflags" -o "$targetDir/" ./cmd/flugschreiber ./cmd/proxyd
        if ($LASTEXITCODE) { throw "build failed: $target" }
        Copy-Item README.md, LICENSE, SECURITY.md -Destination $targetDir
        $archive = Join-Path $releaseDir "flugschreiber_${version}_$($env:GOOS)_$($env:GOARCH)"
        if ($env:GOOS -eq 'windows') {
            $archive += '.zip'
            Compress-Archive -Path $targetDir -DestinationPath $archive
        } else {
            $archive += '.tar.gz'
            Push-Location $releaseDir
            try {
                tar -czf ([IO.Path]::GetFileName($archive)) $name
                if ($LASTEXITCODE) { throw "packaging failed: $target" }
            } finally {
                Pop-Location
            }
        }
        $artifacts += $archive
    }
} finally {
    $env:GOOS, $env:GOARCH = $oldGOOS, $oldGOARCH
}
$sums = $artifacts | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $_).Hash.ToLowerInvariant()
    "$hash  $([IO.Path]::GetFileName($_))"
}
$checksumFile = Join-Path $releaseDir 'SHA256SUMS'
[IO.File]::WriteAllText($checksumFile, ($sums -join "`n") + "`n", [Text.UTF8Encoding]::new($false))
& "$releaseDir/flugschreiber_windows_amd64/flugschreiber.exe" version
if ($LASTEXITCODE) { throw 'version smoke test failed' }
```

Check that the displayed version and commit match the intended release. Extract
and smoke-test the other archives on their target operating systems; cross-builds
alone do not exercise those systems. Archives made on Windows do not preserve
Unix executable permissions: run `chmod +x flugschreiber proxyd` inside the
extracted directory on Linux or macOS before running either binary.
To verify downloads on Linux or macOS with
GNU coreutils, run `sha256sum -c SHA256SUMS` beside the five archives. On Windows,
compare `Get-FileHash -Algorithm SHA256` against each line of `SHA256SUMS`.

## Publish when ready

Promote the unreleased patch entry in `CHANGELOG.md` to the version and date,
and save its release notes as `dist/<version>/release-notes.md`. Include the
local gate results and any platform checks not run. The manual artifacts carry
checksums, but no GitHub Actions provenance or keyless cosign signatures; do not
claim the workflow verification described in `SECURITY.md` for these assets.

After reviewing the commit, notes and all five archives, a maintainer can create
a draft release in GitHub's web interface, choose the reviewed commit and
version, and attach the archives, `SHA256SUMS` and release notes.

Review the draft and publish it when ready. This local binary release does not
publish a container image, Helm chart, SBOM or attestation. None of the build or
gate commands above publish, push or tag anything.

Website publication is also manual. Build and validate it locally with
`go run ./cmd/flugschreiber site --out ./dist/site`, then publish the reviewed
output through the hosting provider when authorised.
