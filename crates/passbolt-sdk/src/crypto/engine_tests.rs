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

//! What every engine must do, run on each engine built in.

use std::sync::LazyLock;

use rstest::rstest;

use super::*;

const SERVER_PRIVATE: &str = include_str!("../../tests/fixtures/keys/server_private.asc");
const SERVER_PUBLIC: &str = include_str!("../../tests/fixtures/keys/server_public.asc");
const METADATA_PRIVATE: &str = include_str!("../../tests/fixtures/keys/metadata_private.asc");
const METADATA_PUBLIC: &str = include_str!("../../tests/fixtures/keys/metadata_public.asc");
const ERIN_PRIVATE: &str = include_str!("../../tests/fixtures/keys/erin_private.asc");
const ERIN_PUBLIC: &str = include_str!("../../tests/fixtures/keys/erin_public.asc");
const ERIN_SEIPD_V2_PUBLIC: &str =
    include_str!("../../tests/fixtures/keys/erin_seipd_v2_public.asc");
const ERIN_PASSPHRASE: &str = "erin-passphrase";
const EXPIRED_PUBLIC: &str = include_str!("../../tests/fixtures/keys/expired_public.asc");
const REVOKED_PUBLIC: &str = include_str!("../../tests/fixtures/keys/revoked_public.asc");
/// Written by OpenPGP.js: see `tests/fixtures/messages/README.md`.
const SEIPD_V2_MESSAGE: &str = include_str!("../../tests/fixtures/messages/erin_seipd_v2.asc");
const GNUPG_AEAD_MESSAGE: &str = include_str!("../../tests/fixtures/messages/erin_gnupg_aead.asc");

/// Every engine built in, started once for all tests.
static ENGINES: LazyLock<Vec<OpenPgp>> = LazyLock::new(|| {
    vec![
        OpenPgp::rpgp(),
        #[cfg(all(feature = "openpgpjs", not(target_arch = "wasm32")))]
        OpenPgp::openpgpjs().unwrap(),
    ]
});

fn keypair(openpgp: &OpenPgp, private: &str, public: &str) -> (PrivateKey, PublicKey) {
    (
        openpgp.parse_private_key(private).unwrap(),
        openpgp.parse_public_key(public).unwrap(),
    )
}

#[test]
fn test_every_engine_reads_the_same_fingerprints() {
    for public in [SERVER_PUBLIC, ERIN_PUBLIC, METADATA_PUBLIC] {
        let fingerprints: Vec<String> = ENGINES
            .iter()
            .map(|openpgp| openpgp.public_key_fingerprint(public).unwrap())
            .collect();

        assert!(
            fingerprints.windows(2).all(|pair| pair[0] == pair[1]),
            "{fingerprints:?}"
        );
    }
}

#[rstest]
#[case::private_key_as_public_key(SERVER_PRIVATE)]
#[case::garbage("garbage data")]
fn test_what_is_not_a_public_key_is_refused(#[case] armored: &str) {
    for openpgp in ENGINES.iter() {
        assert!(openpgp.parse_public_key(armored).is_err(), "{openpgp:?}");
    }
}

#[rstest]
#[case::binary(b"secret\r\nwith CR LF".as_slice())]
#[case::empty(b"".as_slice())]
fn test_binary_data_comes_back_as_it_was(#[case] plaintext: &[u8]) {
    for openpgp in ENGINES.iter() {
        let (secret, public) = keypair(openpgp, SERVER_PRIVATE, SERVER_PUBLIC);

        let armored = encrypt_message(plaintext, &[&public]).unwrap();

        assert_eq!(
            decrypt_message(&armored, &secret, "").unwrap(),
            plaintext,
            "{openpgp:?}"
        );
    }
}

#[test]
fn test_signed_text_comes_back_with_lf_line_endings() {
    for openpgp in ENGINES.iter() {
        let (secret, public) = keypair(openpgp, ERIN_PRIVATE, ERIN_PUBLIC);
        let signer = Signer {
            key: &secret,
            passphrase: ERIN_PASSPHRASE,
        };

        let armored = sign_and_encrypt("line one\r\nline two é", &[signer], &[&public]).unwrap();

        assert_eq!(
            decrypt_message(&armored, &secret, ERIN_PASSPHRASE).unwrap(),
            "line one\nline two é".as_bytes(),
            "{openpgp:?}"
        );
    }
}

#[test]
fn test_every_recipient_reads_the_message() {
    for openpgp in ENGINES.iter() {
        let (server_secret, server_public) = keypair(openpgp, SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, metadata_public) =
            keypair(openpgp, METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"both", &[&server_public, &metadata_public]).unwrap();

        for secret in [&server_secret, &metadata_secret] {
            assert_eq!(
                decrypt_message(&armored, secret, "").unwrap(),
                b"both",
                "{openpgp:?}"
            );
        }
    }
}

#[test]
fn test_another_key_does_not_read_the_message() {
    for openpgp in ENGINES.iter() {
        let (_, server_public) = keypair(openpgp, SERVER_PRIVATE, SERVER_PUBLIC);
        let (metadata_secret, _) = keypair(openpgp, METADATA_PRIVATE, METADATA_PUBLIC);

        let armored = encrypt_message(b"secret", &[&server_public]).unwrap();

        assert!(
            decrypt_message(&armored, &metadata_secret, "").is_err(),
            "{openpgp:?}"
        );
    }
}

#[test]
fn test_a_wrong_passphrase_is_refused_even_after_the_right_one() {
    for openpgp in ENGINES.iter() {
        let (secret, public) = keypair(openpgp, ERIN_PRIVATE, ERIN_PUBLIC);
        let armored = encrypt_message(b"secret", &[&public]).unwrap();

        assert!(decrypt_message(&armored, &secret, ERIN_PASSPHRASE).is_ok());
        assert!(
            decrypt_message(&armored, &secret, "wrong").is_err(),
            "{openpgp:?}"
        );
    }
}

#[rstest]
#[case::revoked(REVOKED_PUBLIC)]
#[case::expired(EXPIRED_PUBLIC)]
fn test_no_message_is_written_for_an_unusable_key(#[case] public: &str) {
    for openpgp in ENGINES.iter() {
        let key = openpgp.parse_public_key(public).unwrap();

        assert!(encrypt_message(b"secret", &[&key]).is_err(), "{openpgp:?}");
    }
}

#[rstest]
#[case::seipd_v2(SEIPD_V2_MESSAGE, "9:")]
#[case::gnupg_aead(GNUPG_AEAD_MESSAGE, "7:")]
fn test_aead_messages_and_their_session_keys_are_read(
    #[case] armored: &str,
    #[case] algorithm: &str,
) {
    for openpgp in ENGINES.iter() {
        let erin = openpgp.parse_private_key(ERIN_PRIVATE).unwrap();

        let (plaintext, session_key) =
            decrypt_message_keeping_session_key(armored, &erin, ERIN_PASSPHRASE).unwrap();
        let stored = SessionKey::parse(&session_key.to_passbolt_string()).unwrap();

        assert_eq!(plaintext, b"line one\nline two", "{openpgp:?}");
        assert!(
            session_key.to_passbolt_string().starts_with(algorithm),
            "{openpgp:?}"
        );
        assert_eq!(
            openpgp.decrypt_with_session_key(armored, &stored).unwrap(),
            b"line one\nline two",
            "{openpgp:?}"
        );
    }
}

#[rstest]
#[case::seipd_v1(ERIN_PUBLIC)]
#[case::seipd_v2(ERIN_SEIPD_V2_PUBLIC)]
fn test_a_kept_session_key_reads_its_message_only(#[case] public: &str) {
    for openpgp in ENGINES.iter() {
        let (secret, public) = keypair(openpgp, ERIN_PRIVATE, public);
        let first = encrypt_message(b"first", &[&public]).unwrap();
        let second = encrypt_message(b"second", &[&public]).unwrap();

        let (_, session_key) =
            decrypt_message_keeping_session_key(&first, &secret, ERIN_PASSPHRASE).unwrap();

        assert_eq!(
            openpgp
                .decrypt_with_session_key(&first, &session_key)
                .unwrap(),
            b"first",
            "{openpgp:?}"
        );
        assert!(
            openpgp
                .decrypt_with_session_key(&second, &session_key)
                .is_err(),
            "{openpgp:?}"
        );
    }
}

#[test]
fn test_a_key_of_another_engine_is_refused() {
    let [first, second] = [OpenPgp::rpgp(), ENGINES.last().unwrap().clone()];
    if first.name() == second.name() {
        return;
    }
    let secret = first.parse_private_key(SERVER_PRIVATE).unwrap();
    let public = second.parse_public_key(SERVER_PUBLIC).unwrap();
    let armored = encrypt_message(b"secret", &[&public]).unwrap();

    assert!(decrypt_message(&armored, &secret, "").is_ok());
    assert!(sign_and_encrypt(
        "secret",
        &[Signer {
            key: &secret,
            passphrase: ""
        }],
        &[&public]
    )
    .is_err());
}
