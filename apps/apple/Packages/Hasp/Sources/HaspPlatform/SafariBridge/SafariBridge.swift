public import Foundation
public import HaspKit

/// The Safari side of the extension protocol. Safari has no host process and no peer to verify:
/// the extension is contained in this app's bundle, so the containing app is the only caller. The engine runs
/// here, natively, on the account directory the app shares through the app group.
public struct SafariBridge: Sendable {
  public static let browserName = "safari"
  public static let peer = "safari:kr.jmo.hasp.safari"

  private let session: AccountSession
  private let requiresPresenceToUnlock: Bool

  /// On iOS there is no desktop approval behind an unlock request, so the app's own biometric unlock is the approval.
  public init(session: AccountSession, requiresPresenceToUnlock: Bool = false) {
    self.session = session
    self.requiresPresenceToUnlock = requiresPresenceToUnlock
  }

  /// `frame` is the JSON object the extension passed to `sendNativeMessage`; the result is the JSON reply.
  public func handle(_ frame: Data) async -> Data {
    let request: ExtensionRequest
    do {
      request = try NativeMessage.decodeRequest(frame)
    } catch {
      return Self.error(id: nil, code: .malformed)
    }
    switch request {
    case .enrol(let id, let data): return await pair(id: id, data: data)
    case .unlock(let id, let device, let nonce):
      return await unlock(id: id, device: device, nonce: nonce)
    }
  }

  public static func unavailable(for frame: Data) -> Data {
    let object = (try? JSONSerialization.jsonObject(with: frame)) as? [String: Any]
    let id = (object?["id"] as? NSNumber).flatMap { UInt64(exactly: $0.int64Value) }
    return error(id: id, code: .unavailable)
  }

  private func pair(id: UInt64, data: Data) async -> Data {
    guard let request = PairingRequest.attested(data, browserName: Self.browserName) else {
      return Self.error(id: id, code: .malformed)
    }
    do {
      try await requireUserPresence()
      let link = OneShotLink(request: request)
      _ = try await session.serveExtensionPairing(link: link, peer: Self.peer)
      guard let reply = link.reply else { return Self.error(id: id, code: .unavailable) }
      return try NativeMessage.enrolReply(id: id, payload: reply)
    } catch {
      return Self.error(id: id, code: Self.code(for: error))
    }
  }

  private func unlock(id: UInt64, device: Data, nonce: Data) async -> Data {
    do {
      if requiresPresenceToUnlock { try await requireUserPresence() }
      let released = try await session.releaseExtensionKey(
        device: device.lowercaseHex,
        peer: Self.peer,
        nonce: Base64URL.encode(nonce),
      )
      return try NativeMessage.unlockReply(
        id: id,
        key: released.key.data(),
        validUntil: UInt64(released.validUntil.timeIntervalSince1970),
      )
    } catch {
      return Self.error(id: id, code: Self.code(for: error))
    }
  }

  private func requireUserPresence() async throws {
    guard try await session.status().state != .unlocked else { return }
    try await session.unlockBiometric()
  }

  private static func error(id: UInt64?, code: BridgeErrorCode) -> Data {
    (try? NativeMessage.error(id: id, code: code)) ?? Data("{}".utf8)
  }

  private static func code(for error: any Error) -> BridgeErrorCode {
    switch error as? HaspError {
    case .cancelled, .authz: .declined
    case .deviceRevoked: .revoked
    case .locked: .locked
    case .notFound: .refused
    default: .unavailable
    }
  }
}

private final class OneShotLink: ExtensionLink, @unchecked Sendable {
  // Why: the engine drives one pairing on one thread; the request is consumed before the reply is stored.
  private var request: Data?
  private(set) var reply: Data?

  init(request: Data) {
    self.request = request
  }

  func send(_ message: Data) throws {
    reply = message
  }

  func receive() throws -> Data {
    guard let request else { throw HaspError.authz }
    self.request = nil
    return request
  }
}
