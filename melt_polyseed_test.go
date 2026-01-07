package melt

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/matryer/is"
)

// TestToMnemonicWithLength_Polyseed tests the 16-word polyseed format generation
func TestToMnemonicWithLength_Polyseed(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	// Test 16-word polyseed format
	mnemonic, err := ToMnemonicWithLength(&key, 16, "")
	is.NoErr(err)
	is.True(mnemonic != "")

	// Verify it's 16 words
	words := strings.Fields(mnemonic)
	is.Equal(len(words), 16)

	// Verify it's not empty
	is.True(len(mnemonic) > 0)
}

// TestToMnemonicWithLength_PolyseedWithPassphrase tests polyseed with seed passphrase
func TestToMnemonicWithLength_PolyseedWithPassphrase(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	// Test 16-word polyseed format with passphrase
	mnemonic, err := ToMnemonicWithLength(&key, 16, "test-passphrase")
	is.NoErr(err)
	is.True(mnemonic != "")

	// Verify it's 16 words
	words := strings.Fields(mnemonic)
	is.Equal(len(words), 16)

	// Generate again with same key and passphrase - should produce same result
	mnemonic2, err := ToMnemonicWithLength(&key, 16, "test-passphrase")
	is.NoErr(err)
	is.Equal(mnemonic, mnemonic2)

	// Different passphrase should produce different result
	mnemonic3, err := ToMnemonicWithLength(&key, 16, "different-passphrase")
	is.NoErr(err)
	is.True(mnemonic != mnemonic3)
}

// TestToMnemonicWithLength_AllFormats tests all word count formats
func TestToMnemonicWithLength_AllFormats(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	validCounts := []int{12, 15, 16, 18, 21, 24}

	for _, count := range validCounts {
		t.Run(string(rune(count)), func(t *testing.T) {
			is := is.New(t)
			mnemonic, err := ToMnemonicWithLength(&key, count, "")
			is.NoErr(err)
			is.True(mnemonic != "")

			words := strings.Fields(mnemonic)
			is.Equal(len(words), count)
		})
	}
}

// TestToMnemonicWithLength_InvalidWordCount tests invalid word counts
func TestToMnemonicWithLength_InvalidWordCount(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	invalidCounts := []int{10, 11, 13, 14, 17, 19, 20, 22, 23, 25, 30}

	for _, count := range invalidCounts {
		t.Run(string(rune(count)), func(t *testing.T) {
			is := is.New(t)
			_, err := ToMnemonicWithLength(&key, count, "")
			is.True(err != nil)
		})
	}
}

// TestToMnemonicWithLength_DifferentWordCountsProduceDifferentResults verifies
// that different word counts produce different mnemonics
func TestToMnemonicWithLength_DifferentWordCountsProduceDifferentResults(t *testing.T) {
	is := is.New(t)

	// Generate a test key
	_, key, err := ed25519.GenerateKey(rand.Reader)
	is.NoErr(err)

	mnemonics := make(map[int]string)
	validCounts := []int{12, 15, 16, 18, 21, 24}

	// Generate mnemonics for all word counts
	for _, count := range validCounts {
		mnemonic, err := ToMnemonicWithLength(&key, count, "")
		is.NoErr(err)
		mnemonics[count] = mnemonic
	}

	// Verify all are different
	for i, count1 := range validCounts {
		for j, count2 := range validCounts {
			if i != j {
				is.True(mnemonics[count1] != mnemonics[count2])
			}
		}
	}
}

