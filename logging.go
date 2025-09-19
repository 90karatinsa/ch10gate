package common

import (
	"log"
	"os"
)

var (
	logger = log.New(os.Stderr, "[ch10gate] ", log.LstdFlags|log.Lmicroseconds)
)

func Logf(format string, args ...interface{}) {
	logger.Printf(format, args...)
}

func Fatalf(format string, args ...interface{}) {
	logger.Fatalf(format, args...)
}
