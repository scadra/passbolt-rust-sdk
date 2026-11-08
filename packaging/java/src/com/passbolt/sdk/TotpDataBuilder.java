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
 * Builds the {@link TotpData} of {@link NewResourceBuilder#totp} and
 * {@link ResourceChangesBuilder#totp}: a field left unset takes the server's default on creation
 * and keeps its current value on update.
 *
 * <pre>{@code
 * TotpData totp = new TotpDataBuilder("JBSWY3DPEHPK3PXP").digits(6).build();
 * }</pre>
 */
public final class TotpDataBuilder {
    private String secretKey;
    private String algorithm;
    private Integer digits;
    private Long period;
    private String issuer;

    /** Starts with no field set, to change some fields of an existing TOTP. */
    public TotpDataBuilder() {
    }

    /** Starts with the base32 secret key. */
    public TotpDataBuilder(String secretKey) {
        this.secretKey = secretKey;
    }

    /** The base32 secret key. */
    public TotpDataBuilder secretKey(String secretKey) {
        this.secretKey = secretKey;
        return this;
    }

    /** {@code SHA1}, {@code SHA256} or {@code SHA512}. */
    public TotpDataBuilder algorithm(String algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public TotpDataBuilder digits(int digits) {
        this.digits = digits;
        return this;
    }

    /** Seconds a code is valid. */
    public TotpDataBuilder period(long period) {
        this.period = period;
        return this;
    }

    public TotpDataBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public TotpData build() {
        return new TotpData(secretKey, algorithm, digits, period, issuer);
    }
}
