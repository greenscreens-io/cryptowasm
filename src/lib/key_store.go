/*
 * Copyright (C) 2015, 2023 Green Screens Ltd.
 */
package lib

/**
 *  Generic pointer storage for a given type
 *
 * Example:
 * var rsaPriv = lib.NewKeyStore[rsa.PrivateKey]()
 * var rsaPub = lib.NewKeyStore[rsa.PublicKey]()
 */
type KeyStore[T any] struct {
	store map[string]*T
}

// Get retrieve a value from a map
func (c *KeyStore[T]) Get(id string) *T {
	key, _ := c.store[id]
	return key
}

// Set store a new value to a map
func (c *KeyStore[T]) Set(id string, key *T) string {
	if key != nil {
		c.store[id] = key
	}
	return id
}

// Remove value from map
func (c *KeyStore[T]) Remove(id string) bool {
	sts := c.Exist(id)
	if sts {
		delete(c.store, id)
	}
	return sts
}

// Exist checks if value exist in map
func (c *KeyStore[T]) Exist(id string) bool {
	_, ok := c.store[id]
	return ok
}

// NewKeyStore initialize map storage by given types
func NewKeyStore[T any]() *KeyStore[T] {
	c := KeyStore[T]{}
	c.store = make(map[string]*T)
	return &c
}
