// swift-tools-version: 6.0
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
        .testTarget(
            name: "CheburcertCoreTests",
            dependencies: ["CheburcertCore"],
            resources: [.copy("Fixtures")]
        ),
    ]
)
