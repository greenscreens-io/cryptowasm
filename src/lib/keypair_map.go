/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package lib

/**
*  Generic pointer storage for Private/Public keys
*
* Example:
* var rsaKeyPairStore = lib.NewKeyPairStore[rsa.PrivateKey, rsa.PublicKey]()
* var ecdsaKeyPairStore = lib.NewKeyPairStore[ecdsa.PrivateKey, ecdsa.PublicKey]()
* var ecdhKeyPairStore = lib.NewKeyPairStore[ecdh.PrivateKey, ecdh.PublicKey]()
 */

const idSize = 8

// KeyPairStore a generic memory cache for async keys
type KeyPairStore[K any, P any] struct {
	Private *KeyStore[K]
	Public  *KeyStore[P]
}

// newID generate random id for KeyPairStore
func (c *KeyPairStore[K, P]) newID() string {
	id := randomStr(idSize)
	if c.ExistsAny(id) {
		return c.newID()
	}
	return id
}

// SetKeyPair store public and private key under the same id
// If required t osoter ony one type (usualy public only), set private to nil
func (c *KeyPairStore[K, P]) SetKeyPair(privateKey *K, publicKey *P) string {
	id := c.newID()
	c.Private.Set(id, privateKey)
	c.Public.Set(id, publicKey)
	return id
}

// RemoveKeyPair removes both keys from cache, public and private
// to ermove only one type (usually public), remove directly from public key cache
func (c *KeyPairStore[K, P]) RemoveKeyPair(id string) (bool, bool) {
	return c.Private.Remove(id), c.Public.Remove(id)
}

// GetKeyPair return both matched keys
func (c *KeyPairStore[K, P]) GetKeyPair(id string) (*K, *P) {
	return c.Private.Get(id), c.Public.Get(id)
}

// ExistsKeyPair check if both key types esxist
func (c *KeyPairStore[K, P]) ExistsKeyPair(id string) bool {
	return c.Private.Exist(id) && c.Public.Exist(id)
}

// ExistsAny check if any type of keys exists
func (c *KeyPairStore[K, P]) ExistsAny(id string) bool {
	return c.Private.Exist(id) || c.Public.Exist(id)
}

// Exists check if key exist in a cache
func (c *KeyPairStore[K, P]) Exists(id string, isPublic bool) bool {
	if isPublic {
		return c.Public.Exist(id)
	} else {
		return c.Private.Exist(id)
	}
}

// Remove clears key from a cache, if key is private, cache will remove public also
func (c *KeyPairStore[K, P]) Remove(id string, isPublic bool) bool {
	if isPublic {
		return c.Public.Remove(id)
	}
	c.Public.Remove(id)
	return c.Private.Remove(id)
}

// NewKeyPairStore initialize cache storage by given types
func NewKeyPairStore[K any, P any]() *KeyPairStore[K, P] {
	c := KeyPairStore[K, P]{}
	c.Private = NewKeyStore[K]()
	c.Public = NewKeyStore[P]()
	return &c
}
