// Passbolt ~ Open source password manager for teams
// Copyright (c) Passbolt SA (https://www.passbolt.com)
//
// Licensed under GNU Affero General Public License version 3 of the or any later version.
// For full copyright and license information, please see the LICENSE
// Redistributions of files must retain the above copyright notice.
//
// @copyright     Copyright (c) Passbolt SA (https://www.passbolt.com)
// @license       https://opensource.org/licenses/AGPL-3.0 AGPL License
// @link          https://www.passbolt.com Passbolt(tm)
// @since         0.1.0

package main

import (
	"encoding/json"
	"os"
	"testing"
)

func fixture(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile("../tests/fixtures/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func call(t *testing.T, req request) response {
	t.Helper()
	input, _ := json.Marshal(req)
	var res response
	if err := json.Unmarshal(Call(input), &res); err != nil {
		t.Fatal(err)
	}
	return res
}

// The fixtures OpenPGP.js wrote are read, and their session keys read them again.
func TestTheAeadFixturesAreRead(t *testing.T) {
	erin := fixture(t, "keys/erin_private.asc")
	for message, algorithm := range map[string]uint8{"erin_seipd_v2": 9, "erin_gnupg_aead": 7} {
		armored := fixture(t, "messages/"+message+".asc")
		decrypted := call(t, request{Op: "decryptKeepingSessionKey", Message: armored, Key: erin, Passphrase: "erin-passphrase"})
		again := call(t, request{Op: "decryptWithSessionKey", Message: armored, Algorithm: decrypted.Algorithm, SessionKey: decrypted.SessionKey})

		if decrypted.Error != "" || string(decrypted.Data) != "line one\nline two" || decrypted.Algorithm != algorithm {
			t.Fatalf("%s: %+v", message, decrypted)
		}
		if again.Error != "" || string(again.Data) != "line one\nline two" {
			t.Fatalf("%s again: %+v", message, again)
		}
	}
}

func TestSignedTextComesBackWithLfLineEndings(t *testing.T) {
	erin := fixture(t, "keys/erin_private.asc")
	encrypted := call(t, request{
		Op:         "signAndEncrypt",
		Text:       "line one\r\nline two é",
		Signers:    []signer{{Key: erin, Passphrase: "erin-passphrase"}},
		Recipients: []string{fixture(t, "keys/erin_public.asc")},
	})

	decrypted := call(t, request{Op: "decrypt", Message: encrypted.Message, Key: erin, Passphrase: "erin-passphrase"})

	if decrypted.Error != "" || string(decrypted.Data) != "line one\nline two é" {
		t.Fatalf("%+v %+v", encrypted, decrypted)
	}
}
