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
// @since         0.2.0

package com.passbolt.sdk;

/**
 * Builds the {@link LoginOptions} of {@link PassboltClient#loginWithConfig}: an option left unset
 * keeps its default.
 *
 * <pre>{@code
 * LoginOptions options = new LoginOptionsBuilder()
 *     .serverPublicKey(serverKey.armoredKey())
 *     .timeoutSeconds(30)
 *     .build();
 * }</pre>
 */
public final class LoginOptionsBuilder {
    private boolean tlsSkipVerify;
    private String proxy;
    private String mfaTotpToken;
    private String serverPublicKey;
    private String metadataKeyFingerprint;
    private Long timeoutSeconds;
    private String clientCertificatePem;
    private String clientKeyPem;

    /** Starts with the default options. */
    public LoginOptionsBuilder() {
    }

    /** Accepts any TLS certificate: for a test server only. */
    public LoginOptionsBuilder tlsSkipVerify(boolean tlsSkipVerify) {
        this.tlsSkipVerify = tlsSkipVerify;
        return this;
    }

    /** The proxy URL. */
    public LoginOptionsBuilder proxy(String proxy) {
        this.proxy = proxy;
        return this;
    }

    /** The base32 TOTP secret answering the MFA challenge without prompting. */
    public LoginOptionsBuilder mfaTotpToken(String mfaTotpToken) {
        this.mfaTotpToken = mfaTotpToken;
        return this;
    }

    /**
     * The armored server public key pinned with {@link PassboltFfi#fetchServerKey}: each login
     * then checks the server holds its private key.
     */
    public LoginOptionsBuilder serverPublicKey(String serverPublicKey) {
        this.serverPublicKey = serverPublicKey;
        return this;
    }

    /**
     * The shared metadata key fingerprint pinned with
     * {@link PassboltClient#metadataKeyFingerprint}: shared metadata is then only encrypted for
     * that key.
     */
    public LoginOptionsBuilder metadataKeyFingerprint(String metadataKeyFingerprint) {
        this.metadataKeyFingerprint = metadataKeyFingerprint;
        return this;
    }

    /** Seconds a request may take: 60 by default, 0 waits forever. */
    public LoginOptionsBuilder timeoutSeconds(long timeoutSeconds) {
        if (timeoutSeconds < 0) {
            throw new IllegalArgumentException("timeoutSeconds must not be negative");
        }
        this.timeoutSeconds = timeoutSeconds;
        return this;
    }

    /** The PEM certificate and private key, for a server asking for a client certificate (mTLS). */
    public LoginOptionsBuilder clientCertificate(String certificatePem, String keyPem) {
        this.clientCertificatePem = certificatePem;
        this.clientKeyPem = keyPem;
        return this;
    }

    public LoginOptions build() {
        return new LoginOptions(tlsSkipVerify, proxy, mfaTotpToken, serverPublicKey,
            metadataKeyFingerprint, timeoutSeconds, clientCertificatePem, clientKeyPem);
    }
}
