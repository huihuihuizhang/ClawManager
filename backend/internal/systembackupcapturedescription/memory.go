package systembackupcapturedescription

import (
	"errors"
	"math"
	"runtime/debug"
)

var ErrMemoryDeclaration = errors.New("capture description requires a finite sufficient process memory declaration")

// The template's explicit original byte cap admits process resources at
// startup; actual Seed budgets must also fit this cap before Prepare.
func MemoryBudgetForPlaintext(limit int64) (int64, error) {
	minimum, _ := Budget(1)
	maximum, _ := Budget(MaxMembers)
	if limit < minimum || limit > maximum {
		return 0, ErrMemoryDeclaration
	}
	return 12*limit + (128 << 20), nil
}

func ValidateProcessMemoryDeclaration(plaintextLimit int64) error {
	required, err := MemoryBudgetForPlaintext(plaintextLimit)
	if err != nil {
		return err
	}
	declared := debug.SetMemoryLimit(-1)
	if declared == math.MaxInt64 || declared < required {
		return ErrMemoryDeclaration
	}
	return nil
}

// DecodeMemoryBudget is the explicit admission allowance for the bounded
// in-memory JSON/base64/JCS pipeline. It includes source and output/round-trip
// buffers, decoded copies and GC headroom. It is not an observed RSS claim.
// Producers and consumers must admit one such operation before reading its
// body; unconstrained concurrent maximum-size reads are unsupported.
func DecodeMemoryBudget(seed Seed) (int64, error) {
	if seed.Validate() != nil {
		return 0, ErrDescription
	}
	return MemoryBudgetForPlaintext(seed.MaxPlaintextBytes)
}
