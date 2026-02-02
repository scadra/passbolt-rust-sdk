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

//! The session as a long-lived client (bindings, SDK users) sees it on the real server.

use crate::common::{block_on, sdk_login, Account};

#[test]
fn the_session_check_follows_the_login() {
    let sdk = sdk_login(Account::User);

    assert!(block_on(sdk.check_auth_status()).unwrap());
    block_on(sdk.logout());

    assert!(!block_on(sdk.check_auth_status()).unwrap());
}

#[test]
fn keeping_the_session_alive_keeps_it_usable() {
    let sdk = sdk_login(Account::User);

    block_on(sdk.keep_alive()).unwrap();

    assert!(block_on(sdk.check_auth_status()).unwrap());
    block_on(sdk.logout());
}

#[test]
fn raw_resources_are_searched_by_their_decrypted_name() {
    let name = crate::common::unique_name("searched");
    let resource = crate::common::create_resource(&name, "p", &["--type", "v5-default"]);
    let sdk = sdk_login(Account::User);

    let found = block_on(sdk.get_resources(passbolt_sdk::ResourceQuery {
        search: Some(name.to_uppercase()),
        ..passbolt_sdk::ResourceQuery::default()
    }))
    .unwrap();

    let ids: Vec<&str> = found.iter().map(|found| found.id.as_str()).collect();
    assert_eq!(ids, [resource.id.as_str()]);
    block_on(sdk.logout());
}
