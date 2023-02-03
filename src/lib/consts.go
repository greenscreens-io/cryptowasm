/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package lib

const ERR_INVALID_ARGS_VALIDATION = "invalid argument validation definition"
const ERR_INVALID_ARGS = "invalid number of arguments"
const ERR_INVALID_ARG_TYPE = "invalid argument type"

const ERR_ARRAY_CONVERT = "unable to convert array argument"

const ERR_INVALID_FORMAT = "invalid format"
const ERR_INVALID_HASH = "invalid hash size"
const ERR_INVALID_KEY_RSA = "invalid key size (1024, 2048, 4096) available"
const ERR_INVALID_KEY_EC = "invalid key size (256, 384, 521, 25519) available"

const ERR_KEY_NOT_FOUND = "key not found"
const ERR_KEY_NOT_FOUND_PUB = "public key not found"
const ERR_KEY_NOT_FOUND_PRV = "private key not found"

const ERR_KEY_NOT_IMPORTED = "key not imported"

const ERR_PAD_SIZE = "padded value wasn't in correct size."
const ERR_BLOCK_SIZE = "data: has the wrong block size"
const ERR_MULTI_SIZE = "ciphertext is not a multiple of the block size"

// Format export format type
type Format int

const (
	FormatRaw Format = iota
	FormatPem
	FormatJWK
)
