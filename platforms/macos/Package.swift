// swift-tools-version: 6.2
import PackageDescription

let package = Package(
    name: "SupgangMac",
    platforms: [.macOS(.v15)],
    products: [.executable(name: "supgang-secure-enclave", targets: ["SupgangSecureEnclave"])],
    targets: [
        .executableTarget(
            name: "SupgangSecureEnclave",
            swiftSettings: [.swiftLanguageMode(.v6), .unsafeFlags(["-warnings-as-errors"])],
            linkerSettings: [
                .linkedFramework("CryptoKit"), .linkedFramework("Security"),
                .linkedFramework("LocalAuthentication")
            ]
        )
    ]
)
