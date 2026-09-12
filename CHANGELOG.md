# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

## v0.0.7

**Requires Go 1.27.0.** The `go` directive moves up from 1.26.6, so a consumer on an older
toolchain will not build this version. Nothing else changed here — no source, no signature, no
message text, and the dependency graph is untouched.

### Changed

- **`go` directive 1.26.6 → 1.27.0** — the minimum Go version a consumer needs. The services
  in this project already required 1.27.0 while the libraries were the half still behind, so
  they are brought up together and the whole codebase now asks for one toolchain.

### Notes

- The gate is green on the new directive: `go mod verify`, `go mod tidy -diff`, build, vet,
  `gofmt`, and `go test -race` with **0 races** under a Go 1.27.0 toolchain. `govulncheck`
  reports **0 vulnerabilities this library's code is affected by**. One advisory stands at
  module level — **GO-2026-5932**, the unmaintained `golang.org/x/crypto/openpgp` package. It
  has **no fixed version**, so no bump clears it, and nothing here imports it.

## v0.0.6

Dependency maintenance. No source changed here and nothing this library does behaves
differently.

### Notes

- **`github.com/gmb-eudi/go-eudi-crypto` → v0.0.8** (was v0.0.7) and
  **`github.com/gmb-eudi/go-eudi-trust` → v0.1.2** (was v0.1.1). Both of those are themselves
  source-free dependency releases — neither changed a signature, a message or a behaviour. This
  library calls both directly, and both still answer exactly as before, so no caller of this
  library needs to change anything.

- **Transitive only:** `github.com/lestrrat-go/jwx/v3` → v3.3.0 (was v3.2.0),
  `golang.org/x/crypto` → v0.57.0 (was v0.55.0) and `golang.org/x/sys` → v0.48.0 (was v0.47.0).
  **Nothing here imports jwx or `x/crypto`** — they arrive as indirect requirements through
  `go-eudi-crypto`. The `x/crypto` move crosses v0.56.0, which fixed **GO-2026-6354** and
  **GO-2026-6355** upstream.

- The gate is green on the new set: `go mod verify`, `go mod tidy -diff`, build, vet, `gofmt`,
  and `go test -race` with **0 races** across both test packages — which covers the WRPAC chain,
  WRPRC (including its CWT form), registrar, intended-use, intermediary and registration-
  reference cases, plus the ARF TS5 Registrar API data model and its decoder. `govulncheck`
  reports **0 vulnerabilities this library's code is affected by**. One advisory remains at
  module level — **GO-2026-5932**, the unmaintained `golang.org/x/crypto/openpgp` package. It
  has **no fixed version**, so no bump clears it, and nothing here imports it.

- Repository hygiene, with no effect on code that uses the library: CI now also runs on pushes
  to `develop`, the pinned GitHub Actions moved to their current commits, the `setup-go` pin
  rolled forward to v7.0.0, and `.gitattributes` now pins its own line endings. The README
  no longer claims this library is unpublished — it has been tagged since v0.0.1, and the
  sibling `gmb-eudi` modules it needs resolve from the module proxy.

## v0.0.5

Compatible: no signature changes, no message-text changes, nothing that passed before now
fails.

### Changed

- **Errors now wrap their cause as well as their sentinel — 29 sites** across `anchors.go`,
  `registrar.go`, `ts5/decode.go`, `wrpac.go`, `wrprc.go`, `wrprc_cwt.go` and
  `wrprc_verify.go`. Each was built as `fmt.Errorf("%w: …: %v", ErrSentinel, err)`: the
  sentinel wrapped, the cause printed into the string and then unreachable. Both are now
  `%w`.

  This matters most where the cause carries structure a relying party needs to act on
  differently:

  ```go
  var invalid x509.CertificateInvalidError
  if errors.As(err, &invalid) && invalid.Reason == x509.Expired {
      // the registrar's certificate rotated — not a malformed chain
  }
  ```

  `errors.Is(err, ErrMalformed)` / `ErrWRPRCFormat` still hold and every rendered message is
  byte-identical (`%v` and `%w` print an error the same way), so no existing caller needs to
  change. What is new is that the cause is reachable.

### Dependencies

- `go-eudi-crypto` v0.0.5 → v0.0.6, `go-eudi-trust` v0.0.6 → v0.1.0.
  **`go-eudi-trust` v0.1.0 is a breaking release** — `ResolveIssuerKey` gained a required
  validation-time argument. If you call that function through this library's surface, read
  that library's changelog before bumping.
- `github.com/fxamacker/cbor/v2` v2.9.2 → v2.9.3, `golang.org/x/crypto` v0.54.0 → v0.55.0,
  `github.com/lestrrat-go/dsig` v1.3.0 → v1.4.0 (indirect).

### Notes

- The `go` directive is now `1.26.6`, which is the minimum Go version a consumer needs. The
  previous `1.26` resolved to whatever patch the toolchain happened to have; the exact patch
  is pinned because earlier 1.26 releases carry standard-library security fixes this library's
  callers should not silently miss.
