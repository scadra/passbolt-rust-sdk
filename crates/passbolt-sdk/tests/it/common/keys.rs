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

//! Test-only PGP keys from `tests/fixtures/keys`.

use passbolt_sdk::crypto;
use serde_json::Value;

pub struct TestKey {
    pub name: &'static str,
    pub private: &'static str,
    pub public: &'static str,
    pub passphrase: &'static str,
}

macro_rules! key {
    ($name:literal, $passphrase:literal) => {
        TestKey {
            name: $name,
            private: include_str!(concat!("../../fixtures/keys/", $name, "_private.asc")),
            public: include_str!(concat!("../../fixtures/keys/", $name, "_public.asc")),
            passphrase: $passphrase,
        }
    };
}

pub const ADA: TestKey = key!("ada", "ada-passphrase");
pub const BETTY: TestKey = key!("betty", "betty-passphrase");
pub const CAROL: TestKey = key!("carol", "carol-passphrase");
pub const ERIN: TestKey = key!("erin", "erin-passphrase");
pub const SERVER: TestKey = key!("server", "");
pub const METADATA: TestKey = key!("metadata", "");

pub fn by_name(name: &str) -> &'static TestKey {
    [&ADA, &BETTY, &CAROL, &ERIN, &SERVER, &METADATA]
        .into_iter()
        .find(|key| key.name == name)
        .unwrap_or_else(|| panic!("no fixture key named {name}"))
}

impl TestKey {
    pub fn fingerprint(&self) -> String {
        crypto::parse_private_key(self.private)
            .unwrap()
            .fingerprint
            .clone()
    }

    pub fn encrypt(&self, plaintext: &str) -> String {
        let public_key = crypto::parse_public_key(self.public).unwrap();
        crypto::encrypt_message(plaintext.as_bytes(), &[&public_key]).unwrap()
    }

    pub fn decrypt(&self, armored_message: &str) -> String {
        let private_key = crypto::parse_private_key(self.private).unwrap();
        String::from_utf8(
            crypto::decrypt_message(armored_message, &private_key.key, self.passphrase).unwrap(),
        )
        .unwrap()
    }

    /// Like `decrypt`, `None` when the message is not for this key.
    pub fn try_decrypt(&self, armored_message: &str) -> Option<String> {
        let private_key = crypto::parse_private_key(self.private).unwrap();
        let plaintext =
            crypto::decrypt_message(armored_message, &private_key.key, self.passphrase).ok()?;
        String::from_utf8(plaintext).ok()
    }

    pub fn decrypt_json(&self, armored_message: &str) -> Value {
        serde_json::from_str(&self.decrypt(armored_message)).unwrap()
    }

    /// Decrypt a UTF-8 text message signed by `signers`, outermost signature first, every
    /// signature over the literal data as other `OpenPGP` implementations check them.
    pub fn decrypt_signed(&self, armored_message: &str, signers: &[&Self]) -> String {
        use pgp::{Deserializable, Message};

        let private_key = crypto::parse_private_key(self.private).unwrap();
        let (message, _) =
            Message::from_armor_single(std::io::Cursor::new(armored_message.as_bytes())).unwrap();
        let (mut message, _) = message
            .decrypt(|| self.passphrase.to_string(), &[&private_key.key])
            .unwrap();
        let mut signatures = Vec::new();
        while let Message::Signed {
            message: inner,
            signature,
            ..
        } = message
        {
            signatures.push(signature);
            message = *inner.unwrap();
        }
        let Message::Literal(literal) = message else {
            panic!("no literal data")
        };
        assert!(!literal.is_binary(), "not a text message");
        assert_eq!(signatures.len(), signers.len(), "signature count");
        for (signature, signer) in signatures.iter().zip(signers) {
            signature
                .verify(
                    &crypto::parse_public_key(signer.public).unwrap(),
                    literal.data(),
                )
                .unwrap_or_else(|error| panic!("not signed by {}: {error}", signer.name));
        }
        literal.to_string().unwrap()
    }
}
