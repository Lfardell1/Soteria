//go:build !linux || !amd64

package doctor

import (
	"context"

	"github.com/Lfardell1/Soteria/internal/config"
)

func probeHost(_ context.Context, _ config.Config, r *Report) {
	r.add("runtime_backend", Unsupported, "No native isolation backend is implemented for this platform")
}
