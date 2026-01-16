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

//! What the SDK writes, read by OpenPGP.js, the library of the browser extension
//! (`tests/interop`, set up with `npm ci --prefix tests/interop`).

use std::io::Write;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

use crate::common::keys::TestKey;
use crate::common::*;
use crate::create_v5::{create, github, v5_server};

/// `tests/interop/verify.mjs` on `input`: the decrypted text and each signature's result.
fn openpgp_js(input: &Value) -> Value {
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/interop/verify.mjs"
    );
    let mut node = Command::new("node")
        .arg(script)
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
    let read = openpgp_js(&json!({
        "message": message,
        "decryption_key": key.private,
        "passphrase": key.passphrase,
        "verification_keys": signers.iter().map(|signer| signer.public).collect::<Vec<_>>(),
    }));
    let signatures = read["signatures"].as_array().unwrap();
    assert_eq!(signatures.len(), signers.len(), "{read}");
    for signature in signatures {
        assert_eq!(signature["valid"], true, "{read}");
    }
    read["text"].as_str().unwrap().to_string()
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
    let message = passbolt_sdk::crypto::sign_and_encrypt(
        "line one\nline two",
        &[passbolt_sdk::crypto::Signer {
            key: &signer.key,
            passphrase: ADA.passphrase,
        }],
        &[&passbolt_sdk::crypto::parse_public_key(ADA.public).unwrap()],
    )
    .unwrap();

    assert_eq!(
        read_with_openpgp_js(&message, &ADA, &[&ADA]),
        "line one\nline two"
    );
}
