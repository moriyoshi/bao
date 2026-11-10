//go:build !darwin && !linux

package main

import "os"

func peakRSS(*os.ProcessState) (int64, bool) { return 0, false }
