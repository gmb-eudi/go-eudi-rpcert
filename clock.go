package rpcert

import "time"

// timeNow is the package clock used only by WRPAC.ValidateAgainst, whose
// README-fixed signature carries no clock parameter (WRPRC.Verify takes an
// explicit one). Overridable in tests via export_test.go. Flagged in the
// plan's README-corrections list: a future README revision should inject
// the clock here too (docs/conventions.md "Time" rule).
var timeNow = time.Now
