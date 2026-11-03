// The messages of the Rust errors for `localizedDescription`, next to the generated bindings
// (uniffi.toml omits their `String(reflecting:)` one).
import Foundation

extension PassboltFfiError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case let .Transport(reason): return "Transport error: \(reason)"
        case let .Auth(reason): return "Auth error: \(reason)"
        case let .Crypto(reason): return "Crypto error: \(reason)"
        case let .Api(status, reason): return "API error (\(status)): \(reason)"
        case let .NotFound(reason): return "Not found: \(reason)"
        case let .Config(reason): return "Config error: \(reason)"
        case let .InvalidArgument(reason): return "Invalid argument: \(reason)"
        case let .Other(reason): return reason
        }
    }
}
