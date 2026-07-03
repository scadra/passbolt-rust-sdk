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

//! What the SDK writes, read by OpenPGP.js, the library of the browser extension, and what
//! OpenPGP.js writes, read by the SDK (`tests/interop`, set up with
//! `npm ci --prefix tests/interop`).

use futures_executor::block_on;
use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use passbolt_sdk::{crypto, OpenPgp};
use rstest::rstest;

use crate::common::keys::TestKey;
use crate::common::*;
use crate::create_v5::{create, github, v5_server};

/// The `tests/interop` `script` on `input`.
fn openpgp_js(script: &str, input: &Value) -> Value {
    let mut node = Command::new("node")
        .arg(format!(
            "{}/../../tests/interop/{script}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("node is needed for the interop tests");
    node.stdin
        .take()
        .unwrap()
        .write_all(input.to_string().as_bytes())
        .unwrap();
    let output = node.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "OpenPGP.js (npm ci --prefix tests/interop?): {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

/// Decrypt `message` with `key` in OpenPGP.js, checking it is signed by exactly `signers`.
fn read_with_openpgp_js(message: &str, key: &TestKey, signers: &[&TestKey]) -> String {
    let read = openpgp_js(
        "verify.mjs",
        &json!({
            "message": message,
            "decryption_key": key.private,
            "passphrase": key.passphrase,
            "verification_keys": signers.iter().map(|signer| signer.public).collect::<Vec<_>>(),
        }),
    );
    let signatures = read["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), signers.len(), "{read}");
    for signature in signatures {
        assert_eq!(signature["valid"], true, "{read}");
    }
    read["text"].as_str().unwrap().to_string()
}

/// `text` encrypted for erin by OpenPGP.js in the AEAD `container`.
fn encrypted_by_openpgp_js(text: &str, container: &str) -> String {
    let written = openpgp_js(
        "encrypt.mjs",
        &json!({
            "text": text,
            "container": container,
            "private_key": ERIN.private,
            "passphrase": ERIN.passphrase,
        }),
    );
    written["message"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn shared_metadata_is_signed_by_the_user_and_the_metadata_key() {
    let fake = v5_server(
        json!({"allow_usage_of_personal_keys": false, "zero_knowledge_key_share": false}),
    );

    let body = create(&fake, &github()).await.unwrap();

    let metadata = read_with_openpgp_js(
        body["metadata"].as_str().unwrap(),
        &METADATA,
        &[&ADA, &METADATA],
    );
    assert!(metadata.contains(r#""name":"GitHub""#), "{metadata}");
}

#[tokio::test]
async fn personal_metadata_and_secrets_are_signed_by_the_user() {
    let fake = v5_server(data::metadata_keys_settings());

    let body = create(&fake, &github()).await.unwrap();

    let metadata = read_with_openpgp_js(body["metadata"].as_str().unwrap(), &ADA, &[&ADA]);
    assert!(metadata.contains(r#""name":"GitHub""#), "{metadata}");
    let secret = read_with_openpgp_js(secret_of(&body, ADA_ID), &ADA, &[&ADA]);
    assert!(secret.contains(r#""password":"s3cr3t""#), "{secret}");
}

#[test]
fn multiline_text_keeps_its_line_endings() {
    let signer = passbolt_sdk::crypto::parse_private_key(ADA.private).unwrap();
    let message = block_on(passbolt_sdk::crypto::sign_and_encrypt(
        "line one\nline two",
        &[passbolt_sdk::crypto::Signer {
            key: &signer,
            passphrase: ADA.passphrase,
        }],
        &[&passbolt_sdk::crypto::parse_public_key(ADA.public).unwrap()],
    ))
    .unwrap();

    assert_eq!(
        read_with_openpgp_js(&message, &ADA, &[&ADA]),
        "line one\nline two"
    );
}

/// Every engine built in.
fn engines() -> Vec<OpenPgp> {
    vec![
        OpenPgp::rpgp(),
        #[cfg(feature = "openpgpjs")]
        OpenPgp::openpgpjs().unwrap(),
        #[cfg(feature = "gopenpgp")]
        OpenPgp::gopenpgp(),
    ]
}

#[rstest]
#[case::seipd_v2("seipd_v2")]
#[case::gnupg_aead("gnupg_aead")]
fn aead_messages_of_openpgp_js_are_read_by_every_engine(#[case] container: &str) {
    let message = encrypted_by_openpgp_js(r#"{"password":"s3cr3t"}"#, container);

    for openpgp in engines() {
        let erin = openpgp.parse_private_key(ERIN.private).unwrap();
        let plaintext = block_on(crypto::decrypt_message(&message, &erin, ERIN.passphrase));

        assert_eq!(
            plaintext.unwrap(),
            br#"{"password":"s3cr3t"}"#,
            "{openpgp:?}"
        );
    }
}

/// Shared metadata as each engine writes it, signed by the user and the metadata key: read and
/// checked by OpenPGP.js, and by rpgp.
#[test]
fn what_every_engine_signs_is_checked_by_openpgp_js() {
    for openpgp in engines() {
        let (ada, metadata) = (
            openpgp.parse_private_key(ADA.private).unwrap(),
            openpgp.parse_private_key(METADATA.private).unwrap(),
        );
        let signers = [
            crypto::Signer {
                key: &ada,
                passphrase: ADA.passphrase,
            },
            crypto::Signer {
                key: &metadata,
                passphrase: METADATA.passphrase,
            },
        ];
        let recipient = openpgp.parse_public_key(METADATA.public).unwrap();
        let message = block_on(crypto::sign_and_encrypt(
            "line one\nline two é",
            &signers,
            &[&recipient],
        ))
        .unwrap();

        assert_eq!(
            read_with_openpgp_js(&message, &METADATA, &[&ADA, &METADATA]),
            "line one\nline two é",
            "{openpgp:?}"
        );
        assert_eq!(
            METADATA.decrypt_signed(&message, &[&ADA, &METADATA]),
            "line one\nline two é",
            "{openpgp:?}"
        );
    }
}

#[test]
fn the_session_key_of_a_seipd_v2_message_is_read_by_openpgp_js() {
    let message = encrypted_by_openpgp_js("metadata", "seipd_v2");
    let erin = crypto::parse_private_key(ERIN.private).unwrap();

    let (_, session_key) = block_on(crypto::decrypt_message_keeping_session_key(
        &message,
        &erin,
        ERIN.passphrase,
    ))
    .unwrap();

    let read = openpgp_js(
        "verify.mjs",
        &json!({
            "message": message,
            "session_key": session_key.to_passbolt_string(),
            "verification_keys": [],
        }),
    );
    assert_eq!(read["text"], "metadata");
}

#[test]
fn a_seipd_v2_message_is_read_by_openpgp_js() {
    let erin_asking_for_seipd_v2 = include_str!("../fixtures/keys/erin_seipd_v2_public.asc");
    let signer = crypto::parse_private_key(ADA.private).unwrap();
    let message = block_on(crypto::sign_and_encrypt(
        "line one\nline two",
        &[crypto::Signer {
            key: &signer,
            passphrase: ADA.passphrase,
        }],
        &[&crypto::parse_public_key(erin_asking_for_seipd_v2).unwrap()],
    ))
    .unwrap();

    assert_eq!(
        read_with_openpgp_js(&message, &ERIN, &[&ADA]),
        "line one\nline two"
    );
}
