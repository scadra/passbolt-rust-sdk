// The jar loads its native library (JNA, from the classpath) and maps Rust errors to the
// variants of the checked PassboltException.
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltException;

public class Smoke {
    public static void main(String[] args) throws PassboltException {
        try {
            PassboltFfi.getKeyFingerprint("not a key");
        } catch (PassboltException.Crypto error) {
            System.out.println("ok: " + error.reason());
            return;
        }
        throw new IllegalStateException("expected a crypto error");
    }
}
