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
 * Builds the {@link PassphraseGeneratorSettings} of {@link PassboltFfi#generatePassphrase},
 * starting from the defaults of Passbolt: 9 lowercase words of the EFF list joined by spaces.
 *
 * <pre>{@code
 * String passphrase = PassboltFfi.generatePassphrase(
 *     new PassphraseGeneratorSettingsBuilder().words(6).separator("-").build());
 * }</pre>
 */
public final class PassphraseGeneratorSettingsBuilder {
    private int words = 9;
    private String separator = " ";
    private WordCase wordCase = WordCase.LOWERCASE;
    private int minWords = 4;
    private int maxWords = 40;

    /** Starts with the defaults of Passbolt. */
    public PassphraseGeneratorSettingsBuilder() {
    }

    /** Starts with {@code settings}, those of the organization's policies for instance. */
    public PassphraseGeneratorSettingsBuilder(PassphraseGeneratorSettings settings) {
        words = settings.words();
        separator = settings.wordSeparator();
        if (settings.wordCase() != null) {
            wordCase = settings.wordCase();
        }
        minWords = settings.minWords();
        maxWords = settings.maxWords();
    }

    /** The number of words, 4 to 40. */
    public PassphraseGeneratorSettingsBuilder words(int words) {
        this.words = words;
        return this;
    }

    /** The text between the words. */
    public PassphraseGeneratorSettingsBuilder separator(String separator) {
        this.separator = separator;
        return this;
    }

    /** The case of the words. */
    public PassphraseGeneratorSettingsBuilder wordCase(WordCase wordCase) {
        this.wordCase = wordCase;
        return this;
    }

    public PassphraseGeneratorSettings build() {
        return new PassphraseGeneratorSettings(words, separator, wordCase, minWords, maxWords);
    }
}
