// The package links its XCFramework and maps Rust errors to Swift errors.
import Foundation
import PassboltSDK

do {
    _ = try getKeyFingerprint(privateKeyArmored: "not a key")
    fatalError("expected a crypto error")
} catch let error as PassboltError {
    guard case .Crypto = error else { fatalError("expected a crypto error: \(error)") }
    print("ok: \(error.localizedDescription)")
} catch {
    fatalError("expected a PassboltError: \(error)")
}
