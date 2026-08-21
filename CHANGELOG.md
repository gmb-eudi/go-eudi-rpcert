# Changelog

Notable changes to this library, newest first. Versions are git tags; this file is written
for whoever bumps the dependency.

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
