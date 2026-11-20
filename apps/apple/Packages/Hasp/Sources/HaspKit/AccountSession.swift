public import Foundation
import HaspFFI
public import HaspQuickAccessCore
import HaspQuickAccessClient

/// The only holder of the engine `Client`. Calls block, so they run on this actor and never on the main actor.
public actor AccountSession: VaultServing {
  let client: Client
  public nonisolated let events: AsyncStream<SessionEvent>
  private let origin: URL
  private let biometric: any BiometricAuthenticator

  public init(
    directory: URL,
    origin: URL,
    platformName: String = "macos",
    store: any SecureStore,
    biometric: any BiometricAuthenticator,
  ) throws {
    try FileManager.default.createDirectory(
      at: directory,
      withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700],
    )
    let opened = try mapped {
      try Client.open(
        directory: directory.path,
        serverUrl: origin.absoluteString,
        platformName: platformName,
        store: StoreAdapter(store),
        biometric: BiometricAdapter(biometric),
      )
    }
    let (stream, continuation) = AsyncStream<SessionEvent>.makeStream(bufferingPolicy: .unbounded)
    opened.startEvents(
      listener: EventAdapter(continuation, onLocked: { biometric.invalidate() })
    )
    client = opened
    events = stream
    self.origin = origin
    self.biometric = biometric
  }

  public static func previewKit(blob: Data) throws -> KitPreview {
    let preview = try mapped { try parseKitQr(blob: blob) }
    return KitPreview(
      origin: preview.origin,
      login: preview.login,
      serverFingerprint: preview.serverFingerprint,
    )
  }

  public nonisolated func quickAccessEngine() -> any QuickAccessEngine {
    ClientQuickAccessEngine(client: client)
  }

  public nonisolated func cancelCurrentCall() {
    client.cancel()
  }

  public func status() throws -> AccountStatus {
    AccountStatus(try mapped { try client.status() })
  }

  public func serverFingerprint() throws -> String {
    try mapped { try client.serverFingerprint(origin: origin.absoluteString) }
  }

  public func signIn(
    login: String,
    secretKey: String,
    password: String,
    serverFingerprint: String,
  ) throws {
    let request = SignInRequest(
      origin: origin.absoluteString,
      login: login,
      secretKey: Data(secretKey.utf8),
      password: Data(password.utf8),
      serverFingerprint: serverFingerprint,
    )
    try mapped { try client.signIn(request: request) }
  }

  public func signUp(
    login: String,
    code: String,
    password: String,
    serverFingerprint: String,
  ) throws -> EmergencyKit {
    let request = SignUpRequest(
      origin: origin.absoluteString,
      login: login,
      code: Data(code.utf8),
      password: Data(password.utf8),
      serverFingerprint: serverFingerprint,
    )
    let kit = try mapped { try client.signUp(request: request) }
    return EmergencyKit(
      origin: kit.origin,
      login: kit.login,
      serverFingerprint: kit.serverFingerprint,
      secretKey: String(decoding: kit.secretKey, as: UTF8.self),
      documentText: String(decoding: kit.documentText, as: UTF8.self),
      documentPdf: kit.documentPdf,
    )
  }

  public func signInWithKit(blob: Data, password: String) throws {
    try mapped { try client.signInWithKitQr(blob: blob, password: Data(password.utf8)) }
  }

  public func unlockPassword(_ password: String) throws {
    try mapped { try client.unlockPassword(password: Data(password.utf8)) }
  }

  public func enableHardwareUnlock(password: String) throws {
    try mapped { try client.enableHardwareUnlock(password: Data(password.utf8)) }
  }

  public func unlockBiometric() throws {
    try mapped { try client.unlockBiometric() }
  }

  public func lock() {
    client.lock()
    biometric.invalidate()
  }

  public func applyLockTrigger(_ trigger: LockTrigger, elapsed: Duration) throws -> Bool {
    let seconds = UInt64(max(0, elapsed.components.seconds))
    let locked = try mapped {
      try client.applyLockTrigger(trigger: trigger.ffi, elapsedSeconds: seconds)
    }
    if locked { biometric.invalidate() }
    return locked
  }

  public func settings() throws -> AppSettings {
    AppSettings(try mapped { try client.settings() })
  }

  public func setSettings(_ settings: AppSettings) throws {
    try mapped { try client.setSettings(settings: settings.ffi) }
  }

  public func sync() throws -> SyncOutcome {
    let summary = try mapped { try client.sync() }
    return SyncOutcome(
      vaults: Int(summary.vaults),
      changed: Int(summary.changed),
      needsAttention: Int(summary.needsAttention),
    )
  }

  public func startHints() throws {
    try mapped { try client.startHints() }
  }

  public func stopHints() {
    client.stopHints()
  }

  public func devices() throws -> [DeviceSummary] {
    try mapped { try client.devices() }.map {
      DeviceSummary(
        session: $0.session,
        device: $0.device,
        platform: $0.platform,
        label: $0.label,
        current: $0.current,
        revoked: $0.revoked,
      )
    }
  }

  public func revokeDevice(_ device: DeviceSummary) throws {
    try mapped { try client.revokeDevice(session: device.session, device: device.device) }
  }

  public func serveExtensionPairing(link: any ExtensionLink, peer: String) throws -> String {
    try mapped { try client.serveExtensionPairing(channel: LinkAdapter(link), peer: peer) }
  }

  public func releaseExtensionKey(device: String, peer: String, nonce: String) throws -> (
    key: RevealedSecret, validUntil: Date
  ) {
    let release = try mapped {
      try client.releaseExtensionKey(device: device, peer: peer, nonce: nonce)
    }
    return (
      RevealedSecret(release.key),
      Date(timeIntervalSince1970: TimeInterval(release.validUntil)),
    )
  }

  public func forgetExtensionKey(device: String) throws {
    try mapped { try client.forgetExtensionKey(device: device) }
  }
}
