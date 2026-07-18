package ts5_test

import (
	"os"
	"testing"

	"github.com/gmb-eudi/go-eudi-rpcert/ts5"
)

func FuzzDecodeSignedWRPArray(f *testing.F) {
	for _, name := range []string{"wrp-page1.json", "wrp-page2.json"} {
		//nolint:gosec // G304: name is always a compile-time constant fixture filename from this test file, never external input.
		if b, err := os.ReadFile("../testdata/ts5/" + name); err == nil {
			f.Add(b)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"iss":"x","iat":1,"data":[{"claims":[{"path":[]}]}]}`))
	f.Add([]byte(`[[[[[[[[[[[[[[[[`))
	f.Add([]byte(``))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = ts5.DecodeSignedWRPArray(data) // must not panic
		_, _ = ts5.DecodeSignedWRP(data)      // must not panic
	})
}
