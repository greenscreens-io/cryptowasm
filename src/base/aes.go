/*
 * Copyright (C) 2015, 2026 Green Screens Ltd.
 */
package base

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"wasm/cryptowasm/src/lib"
)

func CBCEncrypter(key, data, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	input, err := pad(data, aes.BlockSize)
	if err != nil {
		return nil, err
	}

	if len(input)%aes.BlockSize != 0 {
		return nil, errors.New(lib.ERR_BLOCK_SIZE)
	}

	ciphertext := make([]byte, len(input))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, input)
	return ciphertext, nil
}

func CBCDecrypter(key, data, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := append([]byte(nil), data...)
	// CBC mode always works in whole blocks.
	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New(lib.ERR_MULTI_SIZE)
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	return unpad(ciphertext, aes.BlockSize)
}

func CTREncrypter(key, data, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, len(data))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, data)
	return ciphertext, nil
}

func CTRDecrypter(key, data, iv []byte) ([]byte, error) {
	if len(iv) != aes.BlockSize {
		return nil, errors.New(lib.ERR_INVALID_ARGS_LEN)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := data[:]
	mode := cipher.NewCTR(block, iv)
	mode.XORKeyStream(ciphertext, ciphertext)
	return ciphertext, nil
}

func GCMEencrypter(key, data, iv []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonceSize := len(iv)
	var aesgcm cipher.AEAD

	if nonceSize == 12 {
		aesgcm, err = cipher.NewGCM(block)
	} else {
		aesgcm, err = cipher.NewGCMWithNonceSize(block, nonceSize)
	}
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, iv, data, nil)
	return ciphertext, nil
}

func GCMDecrypter(key, data, iv []byte) ([]byte, error) {

	ciphertext := data
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonceSize := len(iv)
	var aesgcm cipher.AEAD

	if nonceSize == 12 {
		aesgcm, err = cipher.NewGCM(block)
	} else {
		aesgcm, err = cipher.NewGCMWithNonceSize(block, nonceSize)
	}

	if err != nil {
		return nil, err
	}

	return aesgcm.Open(nil, iv, ciphertext, nil)
}

func pad(buf []byte, size int) ([]byte, error) {
	bufLen := len(buf)
	padLen := size - bufLen%size
	padded := make([]byte, bufLen+padLen)
	copy(padded, buf)
	for i := 0; i < padLen; i++ {
		padded[bufLen+i] = byte(padLen)
	}
	return padded, nil
}

func unpad(padded []byte, size int) ([]byte, error) {
	if size <= 0 || len(padded) == 0 || len(padded)%size != 0 {
		return nil, errors.New(lib.ERR_PAD_SIZE)
	}

	padding := int(padded[len(padded)-1])
	if padding == 0 || padding > size || padding > len(padded) {
		return nil, errors.New(lib.ERR_PAD_SIZE)
	}
	for _, value := range padded[len(padded)-padding:] {
		if int(value) != padding {
			return nil, errors.New(lib.ERR_PAD_SIZE)
		}
	}
	return padded[:len(padded)-padding], nil
}
