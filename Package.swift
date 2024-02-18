// swift-tools-version:5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Keychain",
    platforms: [
        .macOS(.v13),
        .iOS(.v16)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "KeychainCli",
            targets: ["KeychainCli"]),
    ],
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(url: "https://github.com/OperatorFoundation/KeychainLinux", from: "2.0.1"),
        .package(url: "https://github.com/OperatorFoundation/KeychainTypes", from: "1.0.1"),
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "KeychainCli",
            dependencies: [
                "KeychainLinux",
                "KeychainTypes",
            ]),
        .testTarget(
            name: "KeychainTests",
            dependencies: ["KeychainCli", "KeychainLinux", "KeychainTypes",]),
    ],
    swiftLanguageVersions: [.v5]
)
