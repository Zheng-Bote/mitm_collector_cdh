// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestValidateKEK(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	encoded := base64.StdEncoding.EncodeToString(key)

	got, err := validateKEK(encoded)
	if err != nil {
		t.Fatalf("validateKEK returned an error: %v", err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("validateKEK returned an unexpected decoded key")
	}
	if _, err := validateKEK("too short"); err == nil {
		t.Fatal("validateKEK accepted an invalid key")
	}
}

func TestUnwrapDEK(t *testing.T) {
	kek := bytes.Repeat([]byte{1}, 32)
	dek := bytes.Repeat([]byte{2}, 32)
	gcm, err := newGCM(kek)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	wrapped := append(nonce, gcm.Seal(nil, nonce, dek, nil)...)

	got, err := unwrapDEK(kek, wrapped)
	if err != nil {
		t.Fatalf("unwrapDEK returned an error: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("unwrapDEK returned an unexpected DEK")
	}
}

func TestSnapshotCursorIgnoresSurroundingWhitespace(t *testing.T) {
	if snapshotCursor([]byte(" {\"id\":1}\n")) != snapshotCursor([]byte("{\"id\":1}")) {
		t.Fatal("snapshot cursor should ignore surrounding whitespace")
	}
}
