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

use secrecy::SecretString;

use crate::crypto::OpenPgp;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// SDK-level configuration: everything needed to connect and authenticate.
///
/// No file I/O — this is a pure data struct suitable for library consumers.
/// `ZeroizeOnDrop` ensures the private key and passphrase are wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SdkConfig {
    pub server_url: String,
    pub private_key_armored: String,
    pub passphrase: SecretString,
    /// "interactive-totp" | "non-interactive-totp" | "none"
    pub mfa_mode: String,
    pub mfa_totp_token: String,
    pub mfa_totp_offset: i64,
    pub mfa_retrys: u32,
    pub tls_skip_verify: bool,
    pub tls_client_cert: String,
    pub tls_client_private_key: String,
    pub proxy: String,
    /// Server public key pinned by `passbolt verify`: proven at each login with a fresh token.
    pub server_public_key: String,
    /// Fingerprint of the shared metadata key pinned by `passbolt verify`: new shared metadata
    /// is not encrypted for another key. Empty: any active key.
    pub metadata_key_fingerprint: String,
    /// go-passbolt-cli verification: a token encrypted for the server, sent again at each login…
    pub server_verify_enc_token: String,
    /// …and the token the server must return.
    pub server_verify_token: String,
    /// The `OpenPGP` engine keys are read and messages written with.
    #[zeroize(skip)]
    pub openpgp: OpenPgp,
}
