// The jar loads its native library (JNA, from the classpath) and maps Rust errors to exceptions.
public class Smoke {
    public static void main(String[] args) {
        try {
            com.passbolt.sdk.PassboltFfi.getKeyFingerprint("not a key");
        } catch (Exception error) {
            System.out.println("ok: " + error);
            return;
        }
        throw new IllegalStateException("expected a crypto error");
    }
}
