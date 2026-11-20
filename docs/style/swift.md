# Swift style

Rules for all Swift in the vault Apple apps: one SwiftUI codebase for macOS and iOS, the AutoFill Credential Provider extension, the Safari Web Extension handler, the macOS Quick Access `NSPanel`, and the local SwiftPM packages around the Rust core (UniFFI). Shared rules (comments, secrets, errors, tests, dependencies, commits) are in [README.md](README.md). Tool versions are in the appendix.

## Principles

- Code explains itself. Use names, types and structure, not comments.
- Secret plaintext lives in Rust. Swift holds handles, ids and non-secret overviews. Swift cannot promise to erase memory, so the design must not depend on it.
- Prefer Apple frameworks and the standard library.
- Make invalid states unrepresentable. Choose the obvious solution over the clever one.
- The extension memory budget is a design constraint, not an optimisation.

## Comments

| Allowed | Example |
|---|---|
| Directives the toolchain reads, a suppression followed by a why line | `// swift-tools-version: 6.2`, `// swift-format-ignore: NeverForceUnwrap` |
| Doc comment (`///`) on public API of packages | `/// Throws `HaspError.locked` until `unlock()` has run.` |
| Why-comment | `// Why: ASCredentialProviderViewController is torn down after completeRequest (<doc URL>)` |
| Why-comment naming the guard for `@unchecked Sendable` or `nonisolated(unsafe)` | `// Why: guarded by one lock (<URL>)` |

- **No `// MARK:` dividers.** Split the file or use an extension per conformance. Google's guide suggests MARK comments to group members `[V]`; this file departs (table at the end).
- **Docs:** `///` only, no `/** */`, no `- Parameter` lists unless a parameter needs explaining. Unexported and test code have no doc comments. `AllPublicDeclarationsHaveDocumentation` is off.
- **CI greps for the rest** (CI gates).

## Formatting and tooling

- `swift format` (swift-format, ships in the toolchain) formats and lints everything except generated bindings `[V]`. Config in the appendix. `swift format lint --strict -r <paths>` must exit 0. Defaults apply: 2-space indent, 100 columns, one blank line maximum. If a line is too long, extract a name.
- Trailing commas in every multi-line list. Imports are sorted and grouped by `OrderedImports`. Import only what the file uses.
- `-warnings-as-errors` in every target (`.treatAllWarnings(as: .error)` and `SWIFT_TREAT_WARNINGS_AS_ERRORS`). A warning that cannot be fixed is suppressed at the smallest scope with a why-comment.
- Generated UniFFI Swift is committed, never formatted, never edited, and excluded by passing explicit paths to the linter. `[U]` swift-format has no ignore-file in the config schema.
- No SwiftLint and no SwiftFormat (nicklockwood). One formatter. Rules it lacks are CI greps or review rules.

## Naming

- **The Swift API Design Guidelines are binding** `[V]`. Acronyms are uniformly cased: `itemID`, `ItemID`, `urlString`, `TOTPCode`.
- **No `Manager`, `Helper`, `Utils`, `Handler` (except the Safari entry point Apple names), `Service` without a role.** Name the thing: `UnlockCoordinator`, `ClipboardClearer`.
- **No `get` prefix, no leading underscores** (`NoLeadingUnderscores`).
- **One main type per file, named after it:** `AccountSession.swift`, `AccountSession+Unlock.swift`. Small related types may share a file named for the concept.
- **Test names are behaviour sentences without a `test` prefix:** `@Test func summariesThrowWhileLocked()`.
- **Targets and modules:** `Hasp` prefix, `UpperCamelCase`: `HaspKit`, `HaspPlatform`, `HaspUI`, `HaspFFI`. Bundle ids are `kr.jmo.hasp.*`.

## Packages, files and access control

- **All logic lives in one local SwiftPM package, `Packages/Vault`.** Apps and extensions contain only entry points, `Info.plist`, entitlements and wiring.

| Target | Contents | Swift mode | Default isolation |
|---|---|---|---|
| `HaspFFI` | UniFFI generated Swift + XCFramework binary target | 5 | nonisolated |
| `HaspKit` | facade over `Client`, models, lock policy, errors | 6 | nonisolated (actors) |
| `HaspPlatform` | Keychain, LocalAuthentication, pasteboard, Secure Enclave | 6 | nonisolated |
| `HaspUI` | SwiftUI views and `@Observable` models, shared by macOS and iOS | 6 | `MainActor` |
| `HaspQuickAccess` | macOS-only `NSPanel` host (`condition: .when(platforms: [.macOS])`) | 6 | `MainActor` |

- **Dependency arrow:** `HaspFFI` <- `HaspKit` <- `HaspPlatform` <- `HaspUI`. Only `HaspKit` imports `HaspFFI`. No FFI type appears in any other target's API.
- **The AutoFill extension links `HaspKit` and `HaspPlatform` only, never `HaspUI`'s full tree.** Its own small views live in the extension target or a `HaspAutoFillUI` target.
- **Access is the minimum that compiles.** Default `internal`; `package` between targets of this package; `public` only for what another package or an app target calls. No access modifier on an `extension`.
- **`InternalImportsByDefault` and `MemberImportVisibility` are on.** `[V]` A `public` signature that mentions SwiftUI or another target needs `public import`; an unused `public import` is an error.
- **Order in a file:** nested types, stored properties, initialisers, public, internal, private members.
- **No global mutable state and no `static var`.** Singletons only for `Logger` instances and immutable constants. Inject dependencies through initialisers.
- **No `#if` outside platform seams.** A seam is one file per platform (`Pasteboard+macOS.swift`, `Pasteboard+iOS.swift`) behind one protocol.

## Types and values

- **Value types by default.** `final class` only for identity, `@Observable` models, or an AppKit or UIKit subclass; `actor` for shared mutable state. `ExistentialAny` is on: write `any P`. `[V]`
- **Model state as enums with payloads, not flag pairs:** `enum LockState { case locked, unlocked(UnlockedSession) }`.
- **Sendable value types cross isolation boundaries:** `struct ItemSummary: Sendable, Equatable, Identifiable`. No `Any`, `AnyObject` or `NSObject` in API except where a framework requires it.
- **Opaque ids are distinct types,** not `String`: `struct ItemID: Hashable, Sendable { let rawValue: String }`.
- **`~Copyable` for secret buffers** that must not be duplicated and must zero on `deinit` (Security).
- **Protocols are small, defined by the consumer, and exist for a second implementation or a platform seam** (`SecureStore`, `Pasteboard`), never only for mocking.
- **No `Optional` collections and no `Bool?`.** Empty means empty.
- **Time is `Duration`, `Date` or `ContinuousClock.Instant`,** never `Int` seconds. Time-dependent code takes a `Clock`.

## Functions

- **Never default a security-relevant parameter.**
- **No force unwrap, `try!`, `as!` or implicitly unwrapped optionals** (`NeverForceUnwrap`, `NeverUseForceTry`, `NeverUseImplicitlyUnwrappedOptionals`). `[V]` Tests are exempt by the rules themselves. An invariant violation is `preconditionFailure("<what>")`.
- **Exhaustive `switch` without `default`** on enums this repo owns, so a new case breaks the build. Use `@unknown default` for Apple enums.
- **Functions stay under about 40 lines.** Extract by naming, not by comments. No `inout` for return values and no tuples beyond two elements in API.

## Errors

- **Untyped `throws` is the rule.** `[V]` SE-0413: untyped throws "remains the better default", because typed throws constrains a function's evolution. UniFFI throws are untyped too.
- **Typed throws only inside one module for a closed set the caller must handle exhaustively,** and in generic code that only forwards errors (`throws(E)` replacing `rethrows`). Never in `public` or `package` API.
- **`HaspError` mirrors the FFI `HaspError` of `rust.md` case for case,** in `lowerCamelCase` (`.locked`, `.aead`, `.kdfParams`, `.cancelled`, `.internal`). Associated values carry only ids and counts. It never holds a secret and its `description` never includes item content.
- **Map the generated error once, in `HaspKit`.** Views and extensions never see a generated error type.
- **Never `try?` on a security operation.** `try?` is allowed only where failure is irrelevant, with a why-comment. A bare `catch {}` is banned.
- **Never swallow `CancellationError`.** Rethrow it or map it to `.cancelled`.
- **Handle each error once.** Log at the boundary that decides, with a static message and an error category, never the payload.

## Concurrency

- **Swift 6 language mode in every target but `HaspFFI`.** `[V]`
  - `HaspFFI` stays in Swift 5 mode. UniFFI documents only partial Swift 6 support `[S]`. Async foreign-trait codegen failed under mode 6 in 0.31.2 (uniffi-rs #2929, fixed on main by #2943 on 2026-07-15 `[V]`; tags 0.32.0 to 0.32.2 are not confirmed to contain it `[U]`). Re-test at each UniFFI bump and drop the pin only when a clean mode-6 build is proven.
- **Upcoming features on in every mode-6 target:** `NonisolatedNonsendingByDefault`, `InferIsolatedConformances`, `ExistentialAny`, `InternalImportsByDefault`, `MemberImportVisibility`. `[V]` The first two are not defaults before Swift 7.
- **Default isolation is per target:** `HaspUI` and `HaspQuickAccess` use `.defaultIsolation(MainActor.self)`; every other target keeps nonisolated and states isolation explicitly. `[V]` Never `MainActor` default on `HaspKit`, so heavy work cannot land on the main thread by inheritance.
- **Shared mutable state lives in an `actor`,** one per concept (`AccountSession`). No locks, `DispatchQueue`, Combine, completion handlers or `Task.detached` in new code.
- **UniFFI calls are blocking synchronous calls.** Call them from the `HaspKit` actor or a `@concurrent` function, never from a `@MainActor` context. With `NonisolatedNonsendingByDefault` a plain `nonisolated async` function runs on the caller's actor, so mark heavy work `@concurrent`.
- **`@MainActor` is for UI, AppKit or UIKit subclasses, and the models views read.** Do not annotate whole logic types.
- **`Sendable` is not silenced.** `@preconcurrency import` only for Apple frameworks, with a why-comment, removed when the SDK catches up.
- **Cancellation is cooperative and explicit.** UniFFI calls do not observe task cancellation `[S]` (uniffi-rs PR #3057 adds opt-in cancellation and is still open `[V]`), so `try Task.checkCancellation()` before and after each FFI call, and long Rust operations take a cancel token: `await withTaskCancellationHandler { try await run(token) } onCancel: { token.cancel() }`.
- **Structured concurrency first:** `async let`, `TaskGroup`. An unstructured `Task { }` stores its handle and is cancelled by its owner. No fire-and-forget tasks that touch secrets.
- **Lock and background transitions are `AsyncStream`s of a `Sendable` enum** owned by `AccountSession`; views observe the model, not the stream.

## SwiftUI

- **`@Observable` models, `@State` owns, `@Bindable` binds, `@Environment` injects.** No `ObservableObject`, `@Published`, `@StateObject`, `@ObservedObject` or Combine. Models are `final class`, `@MainActor` by target default, with `private(set)` state.
- **A view contains layout and bindings only.** Logic, formatting of vault data, and any call to `HaspKit` live in the model.
- **A view struct is at most 150 lines and `body` at most 40.** Extract subviews as `struct`s, not `some View` computed properties. No `AnyView`.
- **No secrets in `@State`, `@AppStorage`, `@SceneStorage`, environment, or view identity.** A revealed password is a model property that the model clears on lock, on disappear and after a timeout. `[U]` SwiftUI may keep copies in diffing; the displayed `Text` is the only intended copy.
- **Every user-visible string is a localized key** from the string catalog. No concatenated sentences. CI fails on a hard-coded literal in `Text`, `Label` or `Button`.
- **Every custom control has an accessibility label and is keyboard operable;** macOS commands live in `Commands`, not in views.
- **One `#Preview` per screen,** built from fixture models in a `HaspPreviewSupport` target. A preview never opens a Keychain, a vault file or the FFI client.
- **AppKit and UIKit are wrapped once** (`NSViewRepresentable`, `UIViewRepresentable`, `NSHostingView`) in `HaspPlatform` or `HaspQuickAccess`.

## App extensions and the Quick Access panel

- **Budget:** The budget is 30 MB for the iOS provider. `[S]` The ~120 MB jetsam ceiling is a vendor and forum figure; Apple publishes no number. Measure on a real device never from the simulator.
- **The AutoFill extension runs no Argon2 and opens no file larger than the overview index.** Keys come from the shared Keychain access group.
- **Link only `HaspKit` and `HaspPlatform`.** No third-party packages, no JSON of whole vaults, no image assets beyond the icon, no `import SwiftUI` unless the provider screen needs it (measure the cost first). `[U]` Shared code comes from the package; copy-paste between targets is a defect.
- **Keychain access group:** one `kr.jmo.hasp.shared` group in every entitlements file, and items use `kSecAttrAccessGroup` explicitly. `[U]` Check the macOS data-protection keychain requirement (`kSecUseDataProtectionKeychain`).
- **Provider lifecycle:** complete every request exactly once (`completeRequest`, `cancelRequest`) and release session state on completion. No background tasks that outlive `completeRequest`.
- **Safari handler:** stateless per request, no globals, replies only to the closed message set. `[U]` handler lifetime and memory are unmeasured.
- **Quick Access panel:** `NSPanel` subclass with `.nonactivatingPanel` and `canBecomeKey` true, hosting a SwiftUI view in `NSHostingView`, all `@MainActor`. It closes on resign key and on lock, and holds no unlocked state. `[U]` activation behaviour is unmeasured.

## Security

- **Secret plaintext is not a Swift `String`.** `String` and `Data` are copy-on-write and give no guarantee of erasure. Do not write zeroing helpers for them; they would be false comfort.
- **Rust owns secrets** (`zeroize`). Swift receives an opaque handle and asks Rust to act: fill, copy, compare, generate. Avoid `[UInt8]` round trips of secrets.
- **Where plaintext must cross into Swift** (pasteboard, typed fill, reveal), use `SecretBuffer` (appendix: `~Copyable`, heap-allocated, `memset_s` in `deinit`), convert to `String` or `Data` only at the last call, then drop every reference. `[V]` it compiles and runs; `[U]` it cannot prove no framework copy exists.
- **Text fields that take the master password bind a `String`.** Unavoidable in SwiftUI; pass it to Rust immediately, then set the state to `""`. State this limit in the threat model, not in code.
- **Never persist secrets** to `UserDefaults`, files, `@AppStorage`, state restoration or `NSUserActivity`. Disable state restoration for secret-bearing windows.
- **Keychain:** all calls live in `HaspPlatform`. Use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or `...AfterFirstUnlock...` only where the provider needs it), an explicit access group, never `kSecAttrSynchronizable`. `[S]`
- **Biometrics gate a key, not a boolean.** Bind the key to an access control (`SecAccessControl` with `.biometryCurrentSet`) so the system enforces it; an `LAContext.evaluatePolicy` result alone is a patchable `Bool`. `[S]` Secure Enclave keys via `SecKeyCreateRandomKey` with `kSecAttrTokenIDSecureEnclave` where the design needs a hardware key (protocol.md 4.6).
- **Pasteboard:** macOS writes `org.nspasteboard.ConcealedType` and `org.nspasteboard.TransientType` markers (advisory `[V]`); iOS uses `UIPasteboard.general.setItems(_, options: [.localOnly: true, .expirationDate: ...])` `[U: verify on device]`. Clear after the timeout only if `changeCount` is unchanged since our write.
- **Logging:** `os.Logger` only. Messages are static strings; interpolate only enums, counts and ids, each with an explicit `privacy:` argument. Never interpolate item content, titles, URLs, usernames or errors that may embed them. `print`, `dump`, `NSLog` and `debugPrint` are banned (CI grep). Do not rely on redaction as the protection.
- **No `Mirror`, `String(describing:)` or `CustomDebugStringConvertible` on types that can hold secrets.** Such types print `"<redacted>"`.
- **Screen capture and app switcher:** the unlock and reveal screens hide content when `scenePhase != .active` (iOS) and set `NSWindow.sharingType = .none` for the Quick Access panel and reveal windows (macOS). `[U]`
- **Hardened Runtime on, no `get-task-allow` in Release.** No `#if DEBUG` path skips a security check.

## UniFFI boundary

- **One `Client` object, coarse calls**, wrapped in the `AccountSession` actor; nothing else holds a `Client`.
- **Generated code is committed.** CI regenerates and fails on a diff. The UniFFI version is pinned in `mise.toml` and `Cargo.lock`; a bump is its own PR with the regenerated diff and a full mode-6 re-test.
- **Foreign callbacks (`SecureStore`, `Biometric`) are implemented in `HaspPlatform`,** `Sendable` and thread-safe: Rust may call them from any thread. They never touch the main actor synchronously.
- **FFI types never escape `HaspKit`.** Map `Record`s to `Sendable` structs, errors to `HaspError`, handles to opaque ids.
- **FFI calls are never made from a view's `body` or `init`, or from the main actor.**

## Testing

- **Swift Testing for everything but UI tests** `[V]`: `@Test`, `#expect(throws: HaspError.locked)`, `#require`, suites as `struct`s, `arguments:` for parameterised tests. XCTest only for `XCUIApplication` UI tests and `measure`, since Swift Testing has neither `[U: re-check each Xcode release]`.
- **Package tests run with `swift test`** (no simulator), app and UI tests with `xcodebuild test` on macOS and an iOS simulator. Parallel execution is the default; `.serialized` needs a why-comment.
- **Tests are `@MainActor` only when testing UI models.** No real Keychain outside the macOS CI job, which uses a throw-away access group. Use in-memory `SecureStore` fakes.
- **Memory-budget checks for the extension run as a device test,** not in unit tests.

## CI gates

`mise run check` runs these, and CI calls the same task. `<paths>` is the same list in each line.

```sh
swift format lint --strict -r Packages/Vault/Sources Packages/Vault/Tests apps/apple/App
! grep -rnP '^\s*//(?!/)' <paths> | grep -vP '// (Why: |swift-tools-version|swift-format-ignore)'
! grep -rnE '\b(print|dump|NSLog|debugPrint)\(|// MARK|TODO|FIXME' <paths>
swift build --package-path Packages/Vault
swift test --package-path Packages/Vault
xcodegen generate --spec apps/apple/project.yml && git diff --exit-code apps/apple
xcodebuild build -scheme Vault -destination 'generic/platform=macOS'
xcodebuild build -scheme Vault -destination 'generic/platform=iOS Simulator'
xcodebuild test -scheme Vault -destination 'platform=macOS'
```

Generated UniFFI Swift is regenerated and diffed in the `apple-xcframework` task. `Vault.xcodeproj` is generated and gitignored. Signing flags are set only in the release job.

## Sources

Swift API Design Guidelines `[V]`; swift-format `Configuration.md` and `RuleDocumentation.md` `[V]`, cross-checked with `swift format dump-configuration`; Google Swift Style Guide `[V]`; Swift 6 migration guide and SE-0413 `[V]`, SE-0461, SE-0466 and SE-0470 via secondary articles `[S]`; Swift Testing docs `[S]`; UniFFI manual and uniffi-rs issue 2929, PRs 2943 and 3057 `[V]`; Apple AuthenticationServices, LocalAuthentication, Security, `os.Logger`, pasteboard docs `[U]` (not fetched, API facts from prior knowledge); nspasteboard.org `[V]`; memory-ceiling reports from vendor docs and forums `[S]`.

## Where this file departs from the sources, and why

| Topic | Sources say | This file | Reason |
|---|---|---|---|
| Doc comments | API Guidelines and Google: document every public declaration | Only where the signature leaves something out | No-comment rule |
| `// MARK:` | Google: use MARK to describe member groups | Banned | A MARK is a section divider; split the file instead |
| Typed throws | SE-0413 allows it widely inside modules | Untyped by default, typed only internal and closed | UniFFI errors are untyped; public API must evolve |
| Force unwrap | Google: allowed with an invariant comment | Banned, `preconditionFailure` instead | No comments justify it; failure must be named |
| Default isolation | Swift 6.2 guides suggest `MainActor` default for apps | Per target: UI yes, logic no | Keeps FFI and crypto-adjacent work off the main thread by construction |
| Generated UniFFI mode | Swift 6 everywhere | Swift 5 for `HaspFFI` only | Generated async code failed under mode 6 `[V]` |
| Zeroizing Swift secrets | Common advice: `Data.resetBytes` and friends | Secrets stay in Rust; `~Copyable` buffer only at the edge | CoW makes Swift-side zeroing unverifiable |

## Appendix: configuration files

All files below were run in `run/style-scratch/swift`: `swift format lint --strict`, `swift build`, `swift test`, `xcodegen generate`, and `xcodebuild build` for macOS and iOS Simulator (unsigned) succeeded. Versions: Swift 6.4.2 (swiftlang-6.4.2.1.9), swift-format 6.4.4 (`swift format --version`), Xcode 27.2 (27B52), XcodeGen 2.46.0, Swift Testing 2403, macOS 26 on arm64. The scratch package uses a stub `HaspFFI`.

### `.swift-format`

Only options that differ from the defaults. Verified equivalent to the full explicit config via `swift format dump-configuration`.

```json
{
  "version": 1,
  "lineBreakBeforeEachArgument": true,
  "lineBreakBeforeEachGenericRequirement": true,
  "multilineTrailingCommaBehavior": "alwaysUsed",
  "rules": {
    "NeverForceUnwrap": true,
    "NeverUseForceTry": true,
    "NeverUseImplicitlyUnwrappedOptionals": true,
    "NoLeadingUnderscores": true,
    "OmitExplicitReturns": true,
    "UseEarlyExits": true,
    "UseWhereClausesInForLoops": true,
    "ValidateDocumentationComments": true,
    "AlwaysUseLiteralForEmptyCollectionInit": true
  }
}
```

`NeverForceUnwrap` and `NeverUseForceTry` skip test code.

### `Package.swift`

```swift
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
  name: "Vault",
  platforms: [.macOS(.v15), .iOS(.v18)],
  products: [
    .library(name: "HaspKit", targets: ["HaspKit"]),
    .library(name: "HaspUI", targets: ["HaspUI"]),
  ],
  targets: [
    .target(name: "HaspFFI", swiftSettings: [.swiftLanguageMode(.v5)]),
    .target(
      name: "HaspKit",
      dependencies: ["HaspFFI"],
      swiftSettings: strictSettings
    ),
    .target(
      name: "HaspUI",
      dependencies: ["HaspKit"],
      swiftSettings: strictSettings + [.defaultIsolation(MainActor.self)]
    ),
    .testTarget(
      name: "HaspKitTests",
      dependencies: ["HaspKit"],
      swiftSettings: strictSettings
    ),
  ]
)
```

`HaspUI` shows `.defaultIsolation(MainActor.self)`; add the same line to `HaspQuickAccess`. `.macOS(.v15)` and `.iOS(.v18)` are placeholders until the support policy is set. The real `HaspFFI` is a Swift target plus a `.binaryTarget` for the XCFramework.

### Sample `SecretBuffer`

```swift
import Darwin

public struct SecretBuffer: ~Copyable {
  private let storage: UnsafeMutableRawBufferPointer

  public init(copying bytes: some Collection<UInt8>) {
    storage = .allocate(byteCount: max(bytes.count, 1), alignment: 1)
    storage.copyBytes(from: bytes)
  }

  public var count: Int { storage.count }

  public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try body(UnsafeRawBufferPointer(storage))
  }

  deinit {
    memset_s(storage.baseAddress, storage.count, 0, storage.count)
    storage.deallocate()
  }
}
```

### `apps/apple/project.yml`

One multiplatform target per product (`supportedDestinations`), so macOS and iOS share a definition. `[V]` Built for both destinations. Entitlements: both files carry `application-groups` and `keychain-access-groups`; the AutoFill extension and its containing app both carry `com.apple.developer.authentication-services.autofill-credential-provider`, otherwise iOS does not list the extension in Settings. Set `APPLE_TEAM_ID` in the environment.

```yaml
name: Vault
options:
  bundleIdPrefix: kr.jmo.hasp
  createIntermediateGroups: true
  deploymentTarget:
    iOS: "18.0"
    macOS: "15.0"
  xcodeVersion: "2700"
  generateEmptyDirectories: true
settings:
  base:
    SWIFT_VERSION: "6.0"
    SWIFT_STRICT_CONCURRENCY: complete
    SWIFT_TREAT_WARNINGS_AS_ERRORS: YES
    SWIFT_UPCOMING_FEATURE_EXISTENTIAL_ANY: YES
    SWIFT_UPCOMING_FEATURE_NONISOLATED_NONSENDING_BY_DEFAULT: YES
    SWIFT_UPCOMING_FEATURE_INFER_ISOLATED_CONFORMANCES: YES
    ENABLE_HARDENED_RUNTIME: YES
    DEVELOPMENT_TEAM: $(APPLE_TEAM_ID)
    CODE_SIGN_STYLE: Automatic
  configs:
    Release:
      SWIFT_COMPILATION_MODE: wholemodule
      STRIP_INSTALLED_PRODUCT: YES
      DEPLOYMENT_POSTPROCESSING: YES
packages:
  Vault:
    path: .
targetTemplates:
  App:
    type: application
    sources: [App/Shared]
    dependencies:
      - package: Vault
        product: HaspUI
    entitlements:
      path: App/Config/Vault.entitlements
    info:
      path: App/Config/App-Info.plist
      properties:
        CFBundleDisplayName: Vault
        LSMinimumSystemVersion: $(MACOSX_DEPLOYMENT_TARGET)
        UILaunchScreen: {}
  AutoFill:
    type: app-extension
    sources: [App/AutoFill]
    dependencies:
      - package: Vault
        product: HaspKit
    entitlements:
      path: App/Config/AutoFill.entitlements
    info:
      path: App/Config/AutoFill-Info.plist
      properties:
        NSExtension:
          NSExtensionPointIdentifier: com.apple.authentication-services-credential-provider-ui
          NSExtensionPrincipalClass: $(PRODUCT_MODULE_NAME).CredentialProviderViewController
          NSExtensionAttributes:
            ASCredentialProviderExtensionCapabilities:
              ProvidesPasswords: true
              ProvidesPasskeys: true
  Safari:
    type: app-extension
    sources:
      - App/Safari
    dependencies:
      - package: Vault
        product: HaspKit
    entitlements:
      path: App/Config/Vault.entitlements
    info:
      path: App/Config/Safari-Info.plist
      properties:
        NSExtension:
          NSExtensionPointIdentifier: com.apple.Safari.web-extension
          NSExtensionPrincipalClass: $(PRODUCT_MODULE_NAME).SafariWebExtensionHandler
targets:
  Vault:
    templates: [App]
    supportedDestinations: [iOS, macOS]
    dependencies:
      - target: HaspAutoFill
      - target: HaspSafari
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: kr.jmo.hasp
  HaspAutoFill:
    templates: [AutoFill]
    supportedDestinations: [iOS, macOS]
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: kr.jmo.hasp.autofill
  HaspSafari:
    templates: [Safari]
    supportedDestinations: [iOS, macOS]
    settings:
      base:
        PRODUCT_BUNDLE_IDENTIFIER: kr.jmo.hasp.safari
```
