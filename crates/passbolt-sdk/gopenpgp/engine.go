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

// The operations of the gopenpgp engine, as go-passbolt runs them, called from
// `src/crypto/gopenpgp.rs` with a JSON request. Keys are named by their armored text and read
// once; a private key is unlocked once per passphrase, until it is forgotten.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/crypto"
)

type request struct {
	Op         string   `json:"op"`
	Armored    string   `json:"armored"`
	Message    string   `json:"message"`
	Key        string   `json:"key"`
	Passphrase string   `json:"passphrase"`
	Data       []byte   `json:"data"`
	Text       string   `json:"text"`
	Algorithm  uint8    `json:"algorithm"`
	SessionKey []byte   `json:"session_key"`
	Signers    []signer `json:"signers"`
	Recipients []string `json:"recipients"`
}

type signer struct {
	Key        string `json:"key"`
	Passphrase string `json:"passphrase"`
}

type response struct {
	Error       string `json:"error,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Data        []byte `json:"data,omitempty"`
	Message     string `json:"message,omitempty"`
	Algorithm   uint8  `json:"algorithm,omitempty"`
	SessionKey  []byte `json:"session_key,omitempty"`
}

type unlockedKey struct {
	digest [sha256.Size]byte
	key    *crypto.Key
}

var (
	pgp          = crypto.PGP()
	lock         sync.Mutex
	privateKeys  = map[string]*crypto.Key{}
	publicKeys   = map[string]*crypto.Key{}
	unlockedKeys = map[string]unlockedKey{}
)

// The names of the symmetric algorithms, by OpenPGP id.
var algorithms = map[uint8]string{
	7: constants.AES128,
	8: constants.AES192,
	9: constants.AES256,
}

// Call runs the JSON `input` request and gives its JSON response.
func Call(input []byte) []byte {
	var req request
	res, err := response{}, json.Unmarshal(input, &req)
	if err == nil {
		lock.Lock()
		res, err = run(&req)
		lock.Unlock()
	}
	if err != nil {
		res = response{Error: err.Error()}
	}
	output, _ := json.Marshal(res)
	return output
}

func run(req *request) (response, error) {
	switch req.Op {
	case "readPrivateKey":
		key, err := privateKey(req.Armored)
		return fingerprintOf(key), err
	case "readPublicKey":
		key, err := publicKey(req.Armored)
		return fingerprintOf(key), err
	case "forget":
		delete(privateKeys, req.Armored)
		delete(publicKeys, req.Armored)
		if unlocked, held := unlockedKeys[req.Armored]; held {
			unlocked.key.ClearPrivateParams()
			delete(unlockedKeys, req.Armored)
		}
		return response{}, nil
	case "decrypt":
		data, _, err := decrypt(req.Message, req.Key, req.Passphrase, false)
		return response{Data: data}, err
	case "decryptKeepingSessionKey":
		data, sessionKey, err := decrypt(req.Message, req.Key, req.Passphrase, true)
		if err != nil {
			return response{}, err
		}
		algorithm, err := algorithmOf(sessionKey, req.Message)
		return response{Data: data, Algorithm: algorithm, SessionKey: sessionKey.Key}, err
	case "decryptWithSessionKey":
		data, err := decryptWithSessionKey(req.Message, req.Algorithm, req.SessionKey)
		return response{Data: data}, err
	case "encrypt":
		message, err := encrypt(req.Data, false, nil, req.Recipients)
		return response{Message: message}, err
	case "signAndEncrypt":
		message, err := encrypt([]byte(req.Text), true, req.Signers, req.Recipients)
		return response{Message: message}, err
	}
	return response{}, fmt.Errorf("unknown operation %q", req.Op)
}

func fingerprintOf(key *crypto.Key) response {
	if key == nil {
		return response{}
	}
	return response{Fingerprint: strings.ToUpper(key.GetFingerprint())}
}

func privateKey(armored string) (*crypto.Key, error) {
	if key, held := privateKeys[armored]; held {
		return key, nil
	}
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, err
	}
	if !key.IsPrivate() {
		return nil, errors.New("a public key, not a private key")
	}
	privateKeys[armored] = key
	return key, nil
}

func publicKey(armored string) (*crypto.Key, error) {
	if key, held := publicKeys[armored]; held {
		return key, nil
	}
	key, err := crypto.NewKeyFromArmored(armored)
	if err != nil {
		return nil, err
	}
	if key.IsPrivate() {
		return nil, errors.New("a private key, not a public key")
	}
	publicKeys[armored] = key
	return key, nil
}

func unlock(armored, passphrase string) (*crypto.Key, error) {
	digest := sha256.Sum256([]byte(passphrase))
	if unlocked, held := unlockedKeys[armored]; held && unlocked.digest == digest {
		return unlocked.key, nil
	}
	key, err := privateKey(armored)
	if err != nil {
		return nil, err
	}
	locked, err := key.IsLocked()
	if err != nil {
		return nil, err
	}
	if locked {
		if key, err = key.Unlock([]byte(passphrase)); err != nil {
			return nil, err
		}
	}
	unlockedKeys[armored] = unlockedKey{digest: digest, key: key}
	return key, nil
}

func keyRing(keys ...*crypto.Key) (*crypto.KeyRing, error) {
	ring, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if err := ring.AddKey(key); err != nil {
			return nil, err
		}
	}
	return ring, nil
}

// The literal content of `result`: text with LF line endings, binary data as it is.
func content(result *crypto.VerifiedDataResult) []byte {
	data := result.Bytes()
	if result.Metadata().IsUtf8() {
		return bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	}
	return data
}

// As the browser extension: some secrets were encrypted for RSA keys not flagged for encryption.
func decryption() *crypto.DecryptionHandleBuilder {
	return pgp.Decryption().InsecureAllowDecryptionWithSigningKeys()
}

func decrypt(message, armored, passphrase string, keepSessionKey bool) ([]byte, *crypto.SessionKey, error) {
	key, err := unlock(armored, passphrase)
	if err != nil {
		return nil, nil, err
	}
	builder := decryption().DecryptionKey(key)
	if keepSessionKey {
		builder = builder.RetrieveSessionKey()
	}
	handle, err := builder.New()
	if err != nil {
		return nil, nil, err
	}
	result, err := handle.Decrypt([]byte(message), crypto.Armor)
	if err != nil {
		return nil, nil, err
	}
	return content(result), result.SessionKey(), nil
}

// The OpenPGP id of the symmetric algorithm of `sessionKey`, that of the SEIPD v2 container of
// `message` for a session key without one.
func algorithmOf(sessionKey *crypto.SessionKey, message string) (uint8, error) {
	if sessionKey == nil {
		return 0, errors.New("no session key")
	}
	algorithm, err := sessionKey.GetCipherFuncInt()
	if err == nil {
		return uint8(algorithm), nil
	}
	parsed, err := crypto.NewPGPMessageFromArmored(message)
	if err != nil {
		return 0, err
	}
	return seipdV2Algorithm(parsed.DataPacket)
}

func seipdV2Algorithm(dataPacket []byte) (uint8, error) {
	read, err := packet.Read(bytes.NewReader(dataPacket))
	if err != nil {
		return 0, err
	}
	encrypted, isSeipd := read.(*packet.SymmetricallyEncrypted)
	if !isSeipd || encrypted.Version != 2 {
		return 0, errors.New("a session key without algorithm outside SEIPD v2")
	}
	return uint8(encrypted.Cipher), nil
}

func decryptWithSessionKey(message string, algorithm uint8, key []byte) ([]byte, error) {
	name, known := algorithms[algorithm]
	if !known {
		return nil, fmt.Errorf("unsupported session key algorithm %d", algorithm)
	}
	handle, err := decryption().SessionKey(crypto.NewSessionKeyFromToken(key, name)).New()
	if err != nil {
		return nil, err
	}
	result, err := handle.Decrypt([]byte(message), crypto.Armor)
	if err != nil {
		return nil, err
	}
	return content(result), nil
}

func encrypt(data []byte, text bool, signers []signer, armoredRecipients []string) (string, error) {
	recipients := make([]*crypto.Key, 0, len(armoredRecipients))
	for _, armored := range armoredRecipients {
		key, err := publicKey(armored)
		if err != nil {
			return "", err
		}
		recipients = append(recipients, key)
	}
	recipientRing, err := keyRing(recipients...)
	if err != nil {
		return "", err
	}
	builder := pgp.Encryption().Recipients(recipientRing)
	if text {
		signingKeys := make([]*crypto.Key, 0, len(signers))
		for _, signer := range signers {
			key, err := unlock(signer.Key, signer.Passphrase)
			if err != nil {
				return "", err
			}
			signingKeys = append(signingKeys, key)
		}
		signingRing, err := keyRing(signingKeys...)
		if err != nil {
			return "", err
		}
		builder = builder.SigningKeys(signingRing).Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return "", err
	}
	encrypted, err := handle.Encrypt(data)
	if err != nil {
		return "", err
	}
	return encrypted.Armor()
}
