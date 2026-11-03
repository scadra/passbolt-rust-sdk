// swift-tools-version:5.9
// `swift run` from build/smoke-swift, next to the package build/PassboltSDK (.github/workflows/sdk.yml).
import PackageDescription

let package = Package(
    name: "Smoke",
    platforms: [.macOS(.v12)],
    dependencies: [.package(path: "../PassboltSDK")],
    targets: [
        .executableTarget(
            name: "Smoke",
            dependencies: [.product(name: "PassboltSDK", package: "PassboltSDK")]
        ),
    ]
)
