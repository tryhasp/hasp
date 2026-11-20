import Foundation
public import HaspKit
public import HaspProvider
public import Observation

@Observable
public final class ProviderScreenModel {
  public enum Phase: Equatable {
    case unlocking
    case list
    case working
    case confirm
    case failed(ProviderFailure)
  }

  public static let listLimit = 50

  public struct PendingFill: Equatable, Sendable {
    public let title: String
    public let host: String
    let request: ProviderRequest

    public static func == (lhs: Self, rhs: Self) -> Bool {
      lhs.title == rhs.title && lhs.host == rhs.host
    }
  }

  public private(set) var phase: Phase = .unlocking
  public private(set) var rows: [ProviderRow] = []
  public private(set) var pendingFill: PendingFill?
  public var query = ""

  public let intent: ProviderIntent

  private let coordinator: ProviderCoordinator?
  private unowned let responder: any ProviderResponder
  private let configure: @Sendable () async throws -> Void

  public init(
    intent: ProviderIntent,
    coordinator: ProviderCoordinator?,
    responder: any ProviderResponder,
    configure: @escaping @Sendable () async throws -> Void,
  ) {
    self.intent = intent
    self.coordinator = coordinator
    self.responder = responder
    self.configure = configure
  }

  public var searchable: Bool {
    switch intent {
    case .passwords, .oneTimeCodes, .passkeys, .text: true
    case .fill, .register, .configure: false
    }
  }

  public var registrationSubject: PasskeyRegistrationInput? {
    guard case .register(let input) = intent else { return nil }
    return input
  }

  public func start() async {
    phase = .unlocking
    if coordinator == nil, case .configure = intent {
      await fail(await configureError())
      return
    }
    do {
      try await ready().unlock(prompting: true)
    } catch {
      await fail(error)
      return
    }
    await proceed()
  }

  public func reload() async {
    guard phase == .list else { return }
    await loadRows()
  }

  public func select(_ row: ProviderRow) async {
    switch row.action {
    case .entry(let entry):
      await perform(entryRequest(entry), titled: entry.title)
    case .passkey(let passkey):
      await perform(passkeyRequest(passkey))
    case .text(let option):
      await perform(.text(key: option.key, field: option.field))
    }
  }

  public func confirmFill() async {
    guard let pending = pendingFill,
      case .password(let key, let service, let manual, _) = pending.request
    else { return }
    pendingFill = nil
    await perform(.password(key: key, service: service, manual: manual, confirmed: true))
  }

  public func confirmRegistration() async {
    guard case .register(let input) = intent else { return }
    await perform(.passkeyRegistration(input))
  }

  public func cancel() async {
    await coordinator?.finish()
    responder.finish(failing: .userCancelled)
  }

  public func close(after failure: ProviderFailure) async {
    await coordinator?.finish()
    responder.finish(failing: failure)
  }

  private func configureError() async -> any Error {
    do {
      try await configure()
      return ProviderFailure.openApp
    } catch {
      return error
    }
  }

  private func ready() throws -> ProviderCoordinator {
    guard let coordinator else { throw ProviderFailure.openApp }
    return coordinator
  }

  private func proceed() async {
    switch intent {
    case .passwords, .oneTimeCodes, .passkeys, .text:
      phase = .list
      await loadRows()
    case .fill(let request):
      await perform(request.request, titled: request.subject)
    case .register:
      phase = .confirm
    case .configure:
      await runConfigure()
    }
  }

  private func loadRows() async {
    do {
      rows = try await rowsForQuery()
    } catch {
      await fail(error)
    }
  }

  private func rowsForQuery() async throws -> [ProviderRow] {
    let text = query.trimmingCharacters(in: .whitespacesAndNewlines)
    switch intent {
    case .passwords(let identifiers):
      let entries = try await entries(identifiers, text)
      return entries.map { ProviderRow(entry: $0, kind: .password) }
    case .oneTimeCodes(let identifiers):
      let entries = try await entries(identifiers, text).filter(\.hasOneTimeCode)
      return entries.map { ProviderRow(entry: $0, kind: .oneTimeCode) }
    case .passkeys(let parameters, let identifiers):
      let passkeys = try await ready().passkeys(
        rpID: parameters.rpID,
        allowed: parameters.allowedCredentialIDs,
      )
      let matching = passkeys.filter { text.isEmpty || $0.matches(text) }
      let entries = try await entries(identifiers, text)
      return matching.map(ProviderRow.init(passkey:))
        + entries.map { ProviderRow(entry: $0, kind: .password) }
    case .text:
      let options = try await ready().textOptions(matching: text, limit: Self.listLimit)
      return options.map { ProviderRow(text: $0) }
    case .fill, .register, .configure:
      return []
    }
  }

  private func entries(_ identifiers: [String], _ text: String) async throws -> [ProviderEntry] {
    if text.isEmpty {
      return try await ready().entries(matching: identifiers, limit: Self.listLimit)
    }
    return try await ready().search(text, limit: Self.listLimit)
  }

  private func entryRequest(_ entry: ProviderEntry) -> ProviderRequest {
    if case .oneTimeCodes = intent { return .oneTimeCode(key: entry.key) }
    return .password(
      key: entry.key,
      service: entry.hostToConfirm ?? identifiers.first,
      manual: true,
      confirmed: false,
    )
  }

  private func passkeyRequest(_ passkey: ProviderPasskey) -> ProviderRequest {
    guard case .passkeys(let parameters, _) = intent else { return .oneTimeCode(key: passkey.key) }
    return .passkeyAssertion(
      parameters.input(credentialID: passkey.credentialID),
      key: passkey.key,
    )
  }

  private var identifiers: [String] {
    switch intent {
    case .passwords(let identifiers), .oneTimeCodes(let identifiers),
      .passkeys(_, let identifiers):
      identifiers
    case .text, .fill, .register, .configure: []
    }
  }

  private func perform(_ request: ProviderRequest, titled title: String = "") async {
    phase = .working
    do {
      if let check = try await ready().fillCheck(request), check.needsConfirmation {
        pendingFill = PendingFill(title: title, host: check.host, request: request)
        phase = .confirm
        return
      }
      let result = try await ready().provide(request)
      await coordinator?.finish()
      responder.finish(with: result)
    } catch {
      await fail(error)
    }
  }

  private func runConfigure() async {
    phase = .working
    do {
      try await configure()
      await coordinator?.finish()
      responder.finishConfiguration()
    } catch {
      await fail(error)
    }
  }

  private func fail(_ error: any Error) async {
    let failure = ProviderFailure(error, prompting: true)
    switch failure {
    case .userCancelled, .excludedCredential, .notFound, .interactionRequired:
      await close(after: failure)
    case .openApp, .passwordOnly, .failed:
      phase = .failed(failure)
    }
  }
}

extension ProviderPasskey {
  fileprivate func matches(_ text: String) -> Bool {
    [title, userName, displayName, rpID].contains { $0.localizedStandardContains(text) }
  }
}
