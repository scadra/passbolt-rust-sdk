// The jar loads its native library (JNA, from the classpath), maps Rust errors to the variants of
// the checked PassboltException, and its builders give the records the Rust defaults.
import com.passbolt.sdk.AsyncPassboltClient;
import com.passbolt.sdk.LoginOptionsBuilder;
import com.passbolt.sdk.NewResource;
import com.passbolt.sdk.NewResourceBuilder;
import com.passbolt.sdk.PassboltClient;
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltException;
import com.passbolt.sdk.PassphraseGeneratorSettingsBuilder;
import com.passbolt.sdk.PasswordGeneratorSettingsBuilder;
import com.passbolt.sdk.ResourceChangesBuilder;
import com.passbolt.sdk.Strength;
import com.passbolt.sdk.WordCase;

import java.util.List;
import java.util.concurrent.CompletionException;

public class Smoke {
    public static void main(String[] args) throws PassboltException {
        try {
            PassboltFfi.getKeyFingerprint("not a key");
            throw new IllegalStateException("expected a crypto error");
        } catch (PassboltException.Crypto error) {
            System.out.println("ok: " + error.reason());
        }

        NewResource resource = new NewResourceBuilder("GitHub").username("ada").build();
        check(resource.name().equals("GitHub") && resource.username().equals("ada")
            && resource.uris().equals(List.of()) && resource.password() == null, resource);
        var changes = new ResourceChangesBuilder().password("new").build();
        check(changes.password().equals("new") && changes.uris() == null
            && !changes.removeTotp() && !changes.clearExpiry(), changes);

        // The options of a builder cross the FFI, then Rust refuses the key.
        var options = new LoginOptionsBuilder().timeoutSeconds(5).build();
        try {
            PassboltClient.loginWithConfig("http://127.0.0.1:9", "not a key", "", options).close();
            throw new IllegalStateException("expected the login to fail");
        } catch (PassboltException error) {
            System.out.println("ok: login refused, " + error.getClass().getSimpleName());
        }

        // The generator of the extension, its settings built from the defaults.
        String password = PassboltFfi.generatePassword(
            new PasswordGeneratorSettingsBuilder().length(24).build());
        check(password.length() == 24
            && PassboltFfi.secretStrength(password) == Strength.VERY_STRONG, password);
        String passphrase = PassboltFfi.generatePassphrase(
            new PassphraseGeneratorSettingsBuilder().words(5).wordCase(WordCase.UPPERCASE).build());
        check(passphrase.equals(passphrase.toUpperCase()), passphrase);
        var policies = PassboltFfi.defaultPasswordPolicies();
        var fromPolicies = new PasswordGeneratorSettingsBuilder(policies.passwordGeneratorSettings())
            .emoji(true).build();
        check(fromPolicies.maskEmoji() && fromPolicies.length() == 18, fromPolicies);
        System.out.println("ok: generator");

        // The future completes on the SDK's runtime, exceptionally with the variant.
        try {
            AsyncPassboltClient.loginWithConfig("http://127.0.0.1:9", "not a key", "", options).join();
            throw new IllegalStateException("expected the async login to fail");
        } catch (CompletionException error) {
            if (!(error.getCause() instanceof PassboltException.Crypto)) {
                throw new IllegalStateException("not a PassboltException.Crypto", error);
            }
            System.out.println("ok: async login refused, " + error.getCause().getClass().getSimpleName());
        }
    }

    private static void check(boolean condition, Object record) {
        if (!condition) {
            throw new IllegalStateException("unexpected defaults: " + record);
        }
    }
}
