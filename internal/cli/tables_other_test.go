//go:build !darwin && !linux

package cli

import "os"

func peakRSS(*os.ProcessState) (int64, bool) { return 0, false }
