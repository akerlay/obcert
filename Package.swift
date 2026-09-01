// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "CheburcertCore",
    platforms: [.macOS(.v13)],
    products: [
        .library(name: "CheburcertCore", targets: ["CheburcertCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "CheburcertCore",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        // Development-only support for the name-constraint testbed. Deliberately NOT
        // exposed as a product, so App/CheburcertApp/project.yml cannot pull it into the
        // shipped .app — it holds a fake CA generator with retained private keys.
        .target(
            name: "TestbedKit",
            dependencies: [
                "CheburcertCore",
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ]
        ),
        .executableTarget(
            name: "obcert-testbed",
            dependencies: ["TestbedKit", "CheburcertCore"]
        ),
        .testTarget(
            name: "CheburcertCoreTests",
            dependencies: ["CheburcertCore", "TestbedKit"],
            resources: [.copy("Fixtures")]
        ),
        .testTarget(name: "TestbedKitTests", dependencies: ["TestbedKit"]),
    ]
)
