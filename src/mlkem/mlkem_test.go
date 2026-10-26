package mlkem

import (
	"bytes"
	"testing"

	"wasm/cryptowasm/src/lib"
)

func TestRawKeyImportAndEncapsulation(t *testing.T) {
	for _, test := range []struct {
		name string
		size int
	}{
		{name: MLKEM768, size: 768},
		{name: MLKEM1024, size: 1024},
	} {
		t.Run(test.name, func(t *testing.T) {
			privateID, err := GenerateKey(test.size)
			if err != nil {
				t.Fatal(err)
			}
			defer RemoveKey(privateID, false)

			privateRaw, err := ExportPrivateKey(privateID, lib.FormatRaw)
			if err != nil {
				t.Fatal(err)
			}
			publicRaw, err := ExportPublicKey(privateID, lib.FormatRaw)
			if err != nil {
				t.Fatal(err)
			}

			importedPrivateID, err := ImportPrivateKey(privateRaw, test.name)
			if err != nil {
				t.Fatal(err)
			}
			defer RemoveKey(importedPrivateID, false)

			importedPublicID, err := ImportPublicKey(publicRaw)
			if err != nil {
				t.Fatal(err)
			}
			defer RemoveKey(importedPublicID, true)

			privatePEM, err := ExportPrivateKey(privateID, lib.FormatPem)
			if err != nil {
				t.Fatal(err)
			}
			publicPEM, err := ExportPublicKey(privateID, lib.FormatPem)
			if err != nil {
				t.Fatal(err)
			}
			importedPEMPrivateID, err := ImportPrivateKey(privatePEM)
			if err != nil {
				t.Fatal(err)
			}
			defer RemoveKey(importedPEMPrivateID, false)
			importedPEMPublicID, err := ImportPublicKey(publicPEM)
			if err != nil {
				t.Fatal(err)
			}
			defer RemoveKey(importedPEMPublicID, true)

			pemSecret, pemCiphertext, err := Encapsulate(importedPEMPublicID)
			if err != nil {
				t.Fatal(err)
			}
			pemRecovered, err := Decapsulate(importedPEMPrivateID, pemCiphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(pemSecret, pemRecovered) {
				t.Fatal("PEM-imported keys failed the encapsulation round trip")
			}

			sharedSecret, ciphertext, err := Encapsulate(importedPublicID)
			if err != nil {
				t.Fatal(err)
			}
			recovered, err := Decapsulate(importedPrivateID, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sharedSecret, recovered) {
				t.Fatal("decapsulated secret differs from encapsulated secret")
			}
		})
	}
}
