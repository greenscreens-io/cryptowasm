/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package base

import (
	"crypto/rand"
)

// random generate random bytes, use either 16, 24, or 32 bytes to select 128, 192, or 256 bit sizes.
func Random(size int) ([]byte, error) {
	genkey := make([]byte, size)
	_, err := rand.Read(genkey)
	return genkey, err
}
