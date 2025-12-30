// Package melt provides function to create a mnemonic set of keys from a
// ed25519 private key, and restore that key from the same mnemonic set of
// words.
package melt

import (
	"crypto/ed25519"
	"fmt"

	"github.com/tyler-smith/go-bip39"
)

// ToMnemonic takes a ed25519 private key and returns the list of words.
func ToMnemonic(key *ed25519.PrivateKey) (string, error) {
	return toMnemonic(key.Seed())
}

func toMnemonic(seed []byte) (string, error) {
	words, err := bip39.NewMnemonic(seed)
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}

	return words, nil
}

// FromMnemonic takes a mnemonic list of words and returns an ed25519
// private key.
func FromMnemonic(mnemonic string) (ed25519.PrivateKey, error) {
	seed, err := bip39.EntropyFromMnemonic(mnemonic)
	if err != nil {
		return nil, fmt.Errorf("failed to get seed from mnemonic: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// ToMnemonicWithLength takes an ed25519 private key and returns a mnemonic
// phrase of the specified word count. This is an auxiliary utility function.
// The generated phrases cannot be used with FromMnemonic to recover the
// original key if the word count is less than 24.
//
// Valid word counts are: 12, 15, 16, 18, 21, or 24 (BIP39 standard).
// The entropy size is determined by the word count:
//   - 12 words = 128 bits (16 bytes)
//   - 15 words = 160 bits (20 bytes)
//   - 16 words = 176 bits (22 bytes)
//   - 18 words = 192 bits (24 bytes)
//   - 21 words = 224 bits (28 bytes)
//   - 24 words = 256 bits (32 bytes)
func ToMnemonicWithLength(key *ed25519.PrivateKey, wordCount int) (string, error) {
	// Map word count to entropy size in bytes
	entropySizeMap := map[int]int{
		12: 16, // 128 bits
		15: 20, // 160 bits
		16: 22, // 176 bits
		18: 24, // 192 bits
		21: 28, // 224 bits
		24: 32, // 256 bits
	}

	entropySize, ok := entropySizeMap[wordCount]
	if !ok {
		return "", fmt.Errorf("invalid word count: %d (must be 12, 15, 16, 18, 21, or 24)", wordCount)
	}

	// Get the full seed (32 bytes)
	fullSeed := key.Seed()

	// Truncate the seed to the required entropy size
	// For shorter phrases, we use only the first N bytes
	// This means shorter phrases represent a different key, not the original
	entropy := make([]byte, entropySize)
	copy(entropy, fullSeed[:entropySize])

	// Generate the mnemonic from the truncated entropy
	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", fmt.Errorf("could not create a mnemonic set of words: %w", err)
	}

	return words, nil
}
