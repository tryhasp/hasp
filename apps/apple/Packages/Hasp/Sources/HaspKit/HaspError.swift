import HaspFFI

/// Mirrors the FFI error case for case. Carries no item content.
public enum HaspError: Error, Equatable, Sendable {
  case format, version, sig, aead, pin, rollback, fork, roster, kdfParams, epoch, root
  case auth, serverKey, authz, invite, locked, cancelled, offline, notFound, refused
  case pending, readOnly, rateLimited, conflict, quarantined, unconfirmed, deviceRevoked
  case `internal`
}

extension HaspError {
  init(_ error: HaspFFI.HaspError) {
    self =
      switch error {
      case .Format: .format
      case .Version: .version
      case .Sig: .sig
      case .Aead: .aead
      case .Pin: .pin
      case .Rollback: .rollback
      case .Fork: .fork
      case .Roster: .roster
      case .KdfParams: .kdfParams
      case .Epoch: .epoch
      case .Root: .root
      case .Auth: .auth
      case .ServerKey: .serverKey
      case .Authz: .authz
      case .Invite: .invite
      case .Locked: .locked
      case .Cancelled: .cancelled
      case .Offline: .offline
      case .NotFound: .notFound
      case .Refused: .refused
      case .Pending: .pending
      case .ReadOnly: .readOnly
      case .RateLimited: .rateLimited
      case .Conflict: .conflict
      case .Quarantined: .quarantined
      case .Unconfirmed: .unconfirmed
      case .DeviceRevoked: .deviceRevoked
      case .Internal: .internal
      }
  }

  var ffi: HaspFFI.HaspError {
    switch self {
    case .format: .Format
    case .version: .Version
    case .sig: .Sig
    case .aead: .Aead
    case .pin: .Pin
    case .rollback: .Rollback
    case .fork: .Fork
    case .roster: .Roster
    case .kdfParams: .KdfParams
    case .epoch: .Epoch
    case .root: .Root
    case .auth: .Auth
    case .serverKey: .ServerKey
    case .authz: .Authz
    case .invite: .Invite
    case .locked: .Locked
    case .cancelled: .Cancelled
    case .offline: .Offline
    case .notFound: .NotFound
    case .refused: .Refused
    case .pending: .Pending
    case .readOnly: .ReadOnly
    case .rateLimited: .RateLimited
    case .conflict: .Conflict
    case .quarantined: .Quarantined
    case .unconfirmed: .Unconfirmed
    case .deviceRevoked: .DeviceRevoked
    case .internal: .Internal
    }
  }
}

func mapped<T>(_ body: () throws -> T) throws -> T {
  do {
    return try ExecutionGuard.hold(body)
  } catch let error as HaspFFI.HaspError {
    throw HaspError(error)
  } catch let error as HaspError {
    throw error
  } catch is CancellationError {
    throw HaspError.cancelled
  } catch {
    throw HaspError.internal
  }
}
