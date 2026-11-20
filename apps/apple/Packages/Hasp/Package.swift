// swift-tools-version: 6.2
import PackageDescription

let strictSettings: [SwiftSetting] = [
  .swiftLanguageMode(.v6),
  .enableUpcomingFeature("ExistentialAny"),
  .enableUpcomingFeature("InternalImportsByDefault"),
  .enableUpcomingFeature("MemberImportVisibility"),
  .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
  .enableUpcomingFeature("InferIsolatedConformances"),
  .treatAllWarnings(as: .error),
]

let package = Package(
  name: "Hasp",
  defaultLocalization: "ko",
  platforms: [.macOS(.v15), .iOS(.v18)],
  products: [
    .library(name: "HaspFFI", targets: ["HaspFFI"]),
    .library(name: "HaspDesign", targets: ["HaspDesign"]),
    .library(name: "HaspQuickAccessCore", targets: ["HaspQuickAccessCore"]),
    .library(name: "HaspQuickAccess", targets: ["HaspQuickAccess"]),
    .library(name: "HaspQuickAccessClient", targets: ["HaspQuickAccessClient"]),
    .library(name: "HaspKit", targets: ["HaspKit"]),
    .library(name: "HaspPlatform", targets: ["HaspPlatform"]),
    .library(name: "HaspUI", targets: ["HaspUI"]),
    .library(name: "HaspProvider", targets: ["HaspProvider"]),
    .library(name: "HaspProviderUI", targets: ["HaspProviderUI"]),
  ],
  targets: [
    .binaryTarget(
      name: "HaspFFIBinary",
      path: "Frameworks/HaspFFIBinary.xcframework",
    ),
    .target(
      name: "HaspFFI",
      dependencies: ["HaspFFIBinary"],
      swiftSettings: [.swiftLanguageMode(.v5)],
    ),
    .target(
      name: "HaspQuickAccessCore",
      swiftSettings: strictSettings,
    ),
    .target(
      name: "HaspQuickAccess",
      dependencies: ["HaspQuickAccessCore", "HaspDesign"],
      resources: [.process("Resources")],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)],
    ),
    .target(
      name: "HaspQuickAccessClient",
      dependencies: ["HaspQuickAccessCore", "HaspFFI"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspQuickAccessCoreTests",
      dependencies: ["HaspQuickAccessCore"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspQuickAccessTests",
      dependencies: ["HaspQuickAccess", "HaspQuickAccessCore"],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)],
    ),
    .target(
      name: "HaspDesign",
      swiftSettings: strictSettings,
    ),
    .target(
      name: "HaspKit",
      dependencies: ["HaspFFI", "HaspQuickAccessClient"],
      swiftSettings: strictSettings,
    ),
    .target(
      name: "HaspPlatform",
      dependencies: ["HaspKit"],
      swiftSettings: strictSettings,
    ),
    .target(
      name: "HaspUI",
      dependencies: ["HaspKit", "HaspPlatform", "HaspDesign", "HaspQuickAccessCore"],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)],
    ),
    .target(
      name: "HaspProvider",
      dependencies: ["HaspKit", "HaspPlatform"],
      swiftSettings: strictSettings,
    ),
    .target(
      name: "HaspProviderUI",
      dependencies: ["HaspProvider", "HaspKit", "HaspDesign"],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)],
    ),
    .testTarget(
      name: "HaspProviderTests",
      dependencies: ["HaspProvider", "HaspProviderUI", "HaspKit", "HaspPlatform"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspKitTests",
      dependencies: ["HaspKit"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspPlatformTests",
      dependencies: ["HaspPlatform", "HaspKit"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspUIModelTests",
      dependencies: ["HaspUI", "HaspKit"],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)],
    ),
    .testTarget(
      name: "HaspDesignTests",
      dependencies: ["HaspDesign"],
      swiftSettings: strictSettings,
    ),
    .testTarget(
      name: "HaspFFITests",
      dependencies: ["HaspFFI"],
      swiftSettings: strictSettings,
    ),
  ],
)
