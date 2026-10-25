package kmac

import (
	"encoding/binary"

	"golang.org/x/crypto/sha3"
)

// functions for KMAC, KAMC i cShake with secret key

// leftEncode i rightEncode su pomoćne funkcije iz NIST standarda
func leftEncode(value uint64) []byte {
	var b [9]byte
	binary.BigEndian.PutUint64(b[1:], value)

	// Nađi prvi bajt koji nije nula (osim ako je vrijednost 0)
	i := 1
	for i < 8 && b[i] == 0 {
		i++
	}
	n := 9 - i
	b[i-1] = byte(n)
	return b[i-1:]
}

func rightEncode(value uint64) []byte {
	// Slično kao leftEncode, ali broj bajtova ide na kraj
	b := leftEncode(value)
	res := make([]byte, len(b))
	copy(res, b[1:])
	res[len(b)-1] = b[0]
	return res
}

func bytepad(data []byte, w int) []byte {
	z := append(leftEncode(uint64(w)), data...)
	for len(z)%w != 0 {
		z = append(z, 0)
	}
	return z
}

func encodeString(s []byte) []byte {
	return append(leftEncode(uint64(len(s)*8)), s...)
}

// KMAC format input : bytepad(encode_string(K), w) + poruka + right_encode(L)
// block size za cSHAKE128 (za 256 je 136)
func wrapKey(size int, key []byte) []byte {
	w := 0
	switch size {
	case 128:
		w = 168
	case 256:
		w = 136
	}
	prefix := bytepad(encodeString(key), w)
	return prefix
}

func toAlgo(size int, customization []byte) sha3.ShakeHash {
	var fn sha3.ShakeHash
	switch size {
	case 128:
		fn = sha3.NewCShake128([]byte("KMAC"), customization)
	case 256:
		fn = sha3.NewCShake256([]byte("KMAC"), customization)
	}
	return fn
}

/*
func encode() {
	key := []byte("moj-tajni-kljuc")
	msg := []byte("poruka")
	custom := []byte("MojKontekst")
	outLen := uint64(256) // bita

	// KMAC parametri za cSHAKE:
	// N (Function Name) mora biti "KMAC"
	// S (Customization) je tvoj string
	h := sha3.NewCShake128([]byte("KMAC"), custom)

	// KMAC formatiranje ulaza: bytepad(encode_string(K), w) + poruka + right_encode(L)
	w := 168 // block size za cSHAKE128 (za 256 je 136)
	prefix := bytepad(encodeString(key), w)
	
	h.Write(prefix)
	h.Write(msg)
	h.Write(rightEncode(outLen))

	// Čitanje rezultata
	out := make([]byte, outLen/8)
	h.Read(out)

	fmt.Printf("Custom KMAC: %x\n", out)
}
*/