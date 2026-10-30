// The jar loads its native library (JNA, from the classpath) and maps Rust errors to the
// variants of the checked PassboltFfiException.
import com.passbolt.sdk.PassboltFfi;
import com.passbolt.sdk.PassboltFfiException;

public class Smoke {
    public static void main(String[] args) throws PassboltFfiException {
        try {
            PassboltFfi.getKeyFingerprint("not a key");
        } catch (PassboltFfiException.Crypto error) {
            System.out.println("ok: " + error.reason());
            return;
        }
        throw new IllegalStateException("expected a crypto error");
    }
}
