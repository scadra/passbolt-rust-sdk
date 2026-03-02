// swift-tools-version:5.9
// Passbolt SDK for iOS: the Rust library as an XCFramework, under its UniFFI Swift bindings.
import PackageDescription

let package = Package(
    name: "PassboltSDK",
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "PassboltSDK", targets: ["PassboltSDK"]),
    ],
    targets: [
        .binaryTarget(name: "passbolt_ffiFFI", path: "passbolt_ffiFFI.xcframework"),
        .target(
            name: "PassboltSDK",
            dependencies: ["passbolt_ffiFFI"],
            path: "Sources/PassboltSDK"
        ),
    ]
)
