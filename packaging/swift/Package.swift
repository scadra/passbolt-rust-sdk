// swift-tools-version:5.9
// Passbolt SDK for iOS and macOS: the Rust library as an XCFramework, under its UniFFI Swift bindings.
import PackageDescription

let package = Package(
    name: "PassboltSDK",
    platforms: [.iOS(.v15), .macOS(.v12)],
    products: [
        .library(name: "PassboltSDK", targets: ["PassboltSDK"]),
    ],
    targets: [
        .binaryTarget(name: "PassboltSDKFFI", path: "PassboltSDKFFI.xcframework"),
        .target(
            name: "PassboltSDK",
            dependencies: ["PassboltSDKFFI"],
            path: "Sources/PassboltSDK"
        ),
    ]
)
