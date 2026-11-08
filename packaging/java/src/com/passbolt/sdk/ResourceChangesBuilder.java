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

import java.util.List;

/**
 * Builds a {@link ResourceChanges}, the argument of {@link PassboltClient#updateResource}: a field
 * left unset keeps its current value.
 *
 * <pre>{@code
 * client.updateResource(id, new ResourceChangesBuilder().password("new").build());
 * }</pre>
 */
public final class ResourceChangesBuilder {
    private String name;
    private String username;
    private List<String> uris;
    private String description;
    private String note;
    private String password;
    private String pinCode;
    private TotpData totp;
    private boolean removeTotp;
    private String expired;
    private boolean clearExpiry;
    private String metadataFieldsJson;
    private String secretFieldsJson;

    /** Starts with no change. */
    public ResourceChangesBuilder() {
    }

    public ResourceChangesBuilder name(String name) {
        this.name = name;
        return this;
    }

    public ResourceChangesBuilder username(String username) {
        this.username = username;
        return this;
    }

    /** Replaces the URIs. v4 types have a single URI. */
    public ResourceChangesBuilder uris(List<String> uris) {
        this.uris = List.copyOf(uris);
        return this;
    }

    /** Replaces the URIs. v4 types have a single URI. */
    public ResourceChangesBuilder uris(String... uris) {
        return uris(List.of(uris));
    }

    public ResourceChangesBuilder description(String description) {
        this.description = description;
        return this;
    }

    /** The secret note of v5 types. */
    public ResourceChangesBuilder note(String note) {
        this.note = note;
        return this;
    }

    public ResourceChangesBuilder password(String password) {
        this.password = password;
        return this;
    }

    public ResourceChangesBuilder pinCode(String pinCode) {
        this.pinCode = pinCode;
        return this;
    }

    /** The TOTP fields to change. Adding a TOTP switches to the type with a TOTP. */
    public ResourceChangesBuilder totp(TotpData totp) {
        this.totp = totp;
        return this;
    }

    /** Removes the TOTP, switching to the type without TOTP. */
    public ResourceChangesBuilder removeTotp() {
        this.removeTotp = true;
        return this;
    }

    /** The new expiry date, RFC 3339. */
    public ResourceChangesBuilder expired(String expired) {
        this.expired = expired;
        return this;
    }

    /** Clears the expiry. */
    public ResourceChangesBuilder clearExpiry() {
        this.clearExpiry = true;
        return this;
    }

    /** A JSON object of fields set as given, last: the v5 metadata or v4 resource fields. */
    public ResourceChangesBuilder metadataFieldsJson(String metadataFieldsJson) {
        this.metadataFieldsJson = metadataFieldsJson;
        return this;
    }

    /** A JSON object of secret fields set as given, last. */
    public ResourceChangesBuilder secretFieldsJson(String secretFieldsJson) {
        this.secretFieldsJson = secretFieldsJson;
        return this;
    }

    public ResourceChanges build() {
        return new ResourceChanges(name, username, uris, description, note, password, pinCode,
            totp, removeTotp, expired, clearExpiry, metadataFieldsJson, secretFieldsJson);
    }
}
