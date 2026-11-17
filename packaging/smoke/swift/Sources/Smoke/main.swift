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

// The OpenPGP engine of the native library encrypts and decrypts in this host: a test key of the
// repository, CI checking the engine each package is built with.
let engine = openpgpEngine()
let environment = ProcessInfo.processInfo.environment
if let expected = environment["PASSBOLT_EXPECTED_ENGINE"], engine != expected {
    fatalError("engine \(engine), expected \(expected)")
}
let keys = URL(fileURLWithPath: environment["PASSBOLT_SMOKE_KEYS"] ?? "crates/passbolt-sdk/tests/fixtures/keys")
let publicKey = try String(contentsOf: keys.appendingPathComponent("erin_public.asc"), encoding: .utf8)
let privateKey = try String(contentsOf: keys.appendingPathComponent("erin_private.asc"), encoding: .utf8)
let armored = try encryptMessage(plaintext: Data("smoke".utf8), publicKeysArmored: [publicKey])
let plaintext = try decryptMessage(armoredMessage: armored, privateKeyArmored: privateKey, passphrase: "erin-passphrase")
guard plaintext == Data("smoke".utf8) else { fatalError("the message did not come back") }
print("ok: \(engine) encrypts and decrypts")
