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
import java.util.Objects;

/**
 * Builds a {@link NewResource}, the argument of {@link PassboltClient#createResource}: the name is
 * required, every other field is left out unless set.
 *
 * <pre>{@code
 * NewResource resource = new NewResourceBuilder("GitHub")
 *     .username("ada")
 *     .uris("https://github.com")
 *     .password("…")
 *     .build();
 * }</pre>
 *
 * <p>The resource type comes from the fields set and the server's default version, unless
 * {@link #resourceType} names it; fields the type does not have are refused.
 */
public final class NewResourceBuilder {
    private final String name;
    private String resourceType;
    private String username;
    private List<String> uris = List.of();
    private String description;
    private String note;
    private String password;
    private TotpData totp;
    private String pinCode;
    private String folderParentId;
    private String expired;
    private String metadataFieldsJson;
    private String secretFieldsJson;

    /** Starts a resource named {@code name}. */
    public NewResourceBuilder(String name) {
        this.name = Objects.requireNonNull(name, "name");
    }

    /** The type slug: {@code password-and-description}, {@code v5-default}, {@code v5-totp-standalone}… */
    public NewResourceBuilder resourceType(String resourceType) {
        this.resourceType = resourceType;
        return this;
    }

    public NewResourceBuilder username(String username) {
        this.username = username;
        return this;
    }

    /** The URIs, none by default. v4 types have a single URI. */
    public NewResourceBuilder uris(List<String> uris) {
        this.uris = List.copyOf(uris);
        return this;
    }

    /** The URIs, none by default. v4 types have a single URI. */
    public NewResourceBuilder uris(String... uris) {
        return uris(List.of(uris));
    }

    public NewResourceBuilder description(String description) {
        this.description = description;
        return this;
    }

    /** The secret note of v5 types. */
    public NewResourceBuilder note(String note) {
        this.note = note;
        return this;
    }

    public NewResourceBuilder password(String password) {
        this.password = password;
        return this;
    }

    /** The TOTP, built with {@link TotpDataBuilder}. */
    public NewResourceBuilder totp(TotpData totp) {
        this.totp = totp;
        return this;
    }

    public NewResourceBuilder pinCode(String pinCode) {
        this.pinCode = pinCode;
        return this;
    }

    /** The folder to create the resource in, the root by default. */
    public NewResourceBuilder folderParentId(String folderParentId) {
        this.folderParentId = folderParentId;
        return this;
    }

    /** The expiry date, RFC 3339. */
    public NewResourceBuilder expired(String expired) {
        this.expired = expired;
        return this;
    }

    /** A JSON object of fields set as given, last: the v5 metadata or v4 resource fields. */
    public NewResourceBuilder metadataFieldsJson(String metadataFieldsJson) {
        this.metadataFieldsJson = metadataFieldsJson;
        return this;
    }

    /** A JSON object of secret fields set as given, last. */
    public NewResourceBuilder secretFieldsJson(String secretFieldsJson) {
        this.secretFieldsJson = secretFieldsJson;
        return this;
    }

    public NewResource build() {
        return new NewResource(name, resourceType, username, uris, description, note, password,
            totp, pinCode, folderParentId, expired, metadataFieldsJson, secretFieldsJson);
    }
}
