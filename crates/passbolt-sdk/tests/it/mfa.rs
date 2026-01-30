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

use passbolt_sdk::{AuthError, PassboltError, PassboltSdk};

use crate::common::*;

const CODE: &str = "123456";

async fn login_with_codes(
    fake: &FakePassbolt,
    codes: &[&'static str],
) -> Result<Client, PassboltError> {
    login_trying(fake, codes, 3).await
}

async fn login_trying(
    fake: &FakePassbolt,
    codes: &[&'static str],
    max_attempts: u32,
) -> Result<Client, PassboltError> {
    let provider = FixedTotpCodes::new(codes);
    PassboltSdk::login(
        fake.clone(),
        &ada_config(),
        Some(Box::new(provider)),
        max_attempts,
    )
    .await
}

#[tokio::test]
async fn login_completes_mfa_when_the_server_asks_for_it() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let client = login_with_codes(&fake, &[CODE]).await.unwrap();

    assert_eq!(client.user_id, ADA_ID);
    let verification = fake.body_of("POST", "/mfa/verify/totp.json");
    assert_eq!(verification["totp"], CODE);
    assert_eq!(verification["remember"], false);
}

#[tokio::test]
async fn login_without_mfa_provider_reports_mfa_required() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let error = PassboltSdk::login(fake.clone(), &ada_config(), None, 3)
        .await
        .err()
        .unwrap();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::MfaRequired)),
        "{error:?}"
    );
}

#[tokio::test]
async fn mfa_retries_a_rejected_code() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    login_with_codes(&fake, &["000000", CODE]).await.unwrap();

    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 2);
}

#[tokio::test]
async fn mfa_fails_after_the_allowed_attempts() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let error = login_with_codes(&fake, &["000000", "111111", "222222"])
        .await
        .err()
        .unwrap();

    assert!(
        matches!(
            &error,
            PassboltError::Auth(AuthError::MfaFailed { attempts: 3, message })
                if message == "Something went wrong when validating the one-time password."
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_expired_mfa_cookie_is_verified_again_and_the_request_replayed() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.with_directory();
    let client = login_with_codes(&fake, &[CODE, CODE]).await.unwrap();
    fake.expire_mfa();

    let me = client.get_me().await.unwrap();

    assert_eq!(me.id, ADA_ID);
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 2);
}

#[tokio::test]
async fn a_second_challenge_after_verification_is_an_error() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.ignore_mfa_verification();

    let error = login_with_codes(&fake, &[CODE]).await.err().unwrap();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::MfaFailed { .. })),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 1);
}

#[tokio::test]
async fn never_more_than_three_codes_are_tried_whatever_the_attempts_asked() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);

    let error = login_trying(&fake, &["0"; 10], 10).await.err().unwrap();

    assert!(
        matches!(
            error,
            PassboltError::Auth(AuthError::MfaFailed { attempts: 3, .. })
        ),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 3);
    assert!(!fake.user_disabled());
}

#[tokio::test]
async fn the_attempts_stop_when_the_server_ends_the_session() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    // Another client already failed three times since this login: the next two fail too.
    fake.fail_mfa_before(3);

    let error = login_with_codes(&fake, &["000000", "111111", "222222"])
        .await
        .err()
        .unwrap();

    assert!(
        matches!(&error, PassboltError::Auth(AuthError::MfaLockedOut(message)) if message.contains("logged out")),
        "{error:?}"
    );
    assert_eq!(
        fake.requests_to("POST", "/mfa/verify/totp.json").len(),
        2,
        "nothing more after the logout"
    );
}

#[tokio::test]
async fn refused_codes_are_counted_over_the_session() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.with_directory();
    let client = login_with_codes(&fake, &["000000", "111111", CODE, "333333", "444444"])
        .await
        .unwrap();
    fake.expire_mfa();

    let error = client.get_me().await.unwrap_err();

    assert!(
        matches!(
            error,
            PassboltError::Auth(AuthError::MfaFailed { attempts: 1, .. })
        ),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 4);
}

#[tokio::test]
async fn an_account_without_totp_is_told_which_mfa_it_has() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    fake.offer_mfa_providers(&["yubikey", "duo"]);

    let error = login_with_codes(&fake, &[CODE]).await.err().unwrap();

    assert!(
        matches!(&error, PassboltError::Auth(AuthError::MfaUnsupported { providers }) if providers == &["yubikey", "duo"]),
        "{error:?}"
    );
    assert!(fake.requests_to("POST", "/mfa/verify/totp.json").is_empty());
}

#[tokio::test]
async fn checking_the_session_never_answers_the_mfa_challenge() {
    let fake = FakePassbolt::new();
    fake.require_mfa(CODE);
    let client = login_with_codes(&fake, &[CODE]).await.unwrap();
    fake.expire_mfa();

    let error = client.check_auth_status().await.unwrap_err();

    assert!(
        matches!(error, PassboltError::Auth(AuthError::MfaRequired)),
        "{error:?}"
    );
    assert_eq!(fake.requests_to("POST", "/mfa/verify/totp.json").len(), 1);
}
