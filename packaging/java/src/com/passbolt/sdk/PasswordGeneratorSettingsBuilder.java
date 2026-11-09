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
 * Builds the {@link PasswordGeneratorSettings} of {@link PassboltFfi#generatePassword}, starting
 * from the defaults of Passbolt: 18 characters of every set but emoji, without look-alike
 * characters.
 *
 * <pre>{@code
 * String password = PassboltFfi.generatePassword(
 *     new PasswordGeneratorSettingsBuilder().length(24).emoji(true).build());
 * }</pre>
 */
public final class PasswordGeneratorSettingsBuilder {
    private int length = 18;
    private int minLength = 8;
    private int maxLength = 128;
    private boolean upper = true;
    private boolean lower = true;
    private boolean digit = true;
    private boolean parenthesis = true;
    private boolean emoji;
    private boolean char1 = true;
    private boolean char2 = true;
    private boolean char3 = true;
    private boolean char4 = true;
    private boolean char5 = true;
    private boolean excludeLookAlikeChars = true;

    /** Starts with the defaults of Passbolt. */
    public PasswordGeneratorSettingsBuilder() {
    }

    /** Starts with {@code settings}, those of the organization's policies for instance. */
    public PasswordGeneratorSettingsBuilder(PasswordGeneratorSettings settings) {
        length = settings.length();
        minLength = settings.minLength();
        maxLength = settings.maxLength();
        upper = settings.maskUpper();
        lower = settings.maskLower();
        digit = settings.maskDigit();
        parenthesis = settings.maskParenthesis();
        emoji = settings.maskEmoji();
        char1 = settings.maskChar1();
        char2 = settings.maskChar2();
        char3 = settings.maskChar3();
        char4 = settings.maskChar4();
        char5 = settings.maskChar5();
        excludeLookAlikeChars = settings.excludeLookAlikeChars();
    }

    /** The number of characters, 8 to 128. */
    public PasswordGeneratorSettingsBuilder length(int length) {
        this.length = length;
        return this;
    }

    /** {@code A-Z} */
    public PasswordGeneratorSettingsBuilder upper(boolean upper) {
        this.upper = upper;
        return this;
    }

    /** {@code a-z} */
    public PasswordGeneratorSettingsBuilder lower(boolean lower) {
        this.lower = lower;
        return this;
    }

    /** {@code 0-9} */
    public PasswordGeneratorSettingsBuilder digit(boolean digit) {
        this.digit = digit;
        return this;
    }

    /** {@code { [ ( | ) ] }} */
    public PasswordGeneratorSettingsBuilder parenthesis(boolean parenthesis) {
        this.parenthesis = parenthesis;
        return this;
    }

    /** The emoticons of Unicode 6. */
    public PasswordGeneratorSettingsBuilder emoji(boolean emoji) {
        this.emoji = emoji;
        return this;
    }

    /** {@code # $ % & @ ^ ~} */
    public PasswordGeneratorSettingsBuilder char1(boolean char1) {
        this.char1 = char1;
        return this;
    }

    /** {@code . , : ;} */
    public PasswordGeneratorSettingsBuilder char2(boolean char2) {
        this.char2 = char2;
        return this;
    }

    /** {@code ' "} and the backtick. */
    public PasswordGeneratorSettingsBuilder char3(boolean char3) {
        this.char3 = char3;
        return this;
    }

    /** {@code / \ _ -} */
    public PasswordGeneratorSettingsBuilder char4(boolean char4) {
        this.char4 = char4;
        return this;
    }

    /** {@code < * + ! ? =} */
    public PasswordGeneratorSettingsBuilder char5(boolean char5) {
        this.char5 = char5;
        return this;
    }

    /** Leaves out {@code O l | I 0 1}: true by default. */
    public PasswordGeneratorSettingsBuilder excludeLookAlikeChars(boolean excludeLookAlikeChars) {
        this.excludeLookAlikeChars = excludeLookAlikeChars;
        return this;
    }

    public PasswordGeneratorSettings build() {
        return new PasswordGeneratorSettings(length, minLength, maxLength, upper, lower, digit,
            parenthesis, emoji, char1, char2, char3, char4, char5, excludeLookAlikeChars);
    }
}
