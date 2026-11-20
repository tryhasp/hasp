import AuthenticationServices
import Foundation
import HaspKit
import HaspPlatform
import HaspProvider
import HaspProviderUI
import OSLog
import SwiftUI

private let log = Logger(subsystem: "kr.jmo.hasp.autofill", category: "provider")

/// The system credential provider. The system tears this controller down after every
/// request, so each entry point builds its engine, answers once and locks it again.
final class CredentialProviderViewController: ASCredentialProviderViewController,
  ProviderResponder
{
  static let silentReuseWindow = Duration.seconds(60)

  private var session: AccountSession?
  private var coordinator: ProviderCoordinator?
  private var registrationClientDataHash = Data()
  private var work: Task<Void, Never>?

  override func prepareCredentialList(for serviceIdentifiers: [ASCredentialServiceIdentifier]) {
    show(.passwords(identifiers: Self.identifiers(serviceIdentifiers)))
  }

  override func prepareCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier],
    requestParameters: ASPasskeyCredentialRequestParameters,
  ) {
    show(
      .passkeys(
        PasskeyAssertionParameters(requestParameters),
        identifiers: Self.identifiers(serviceIdentifiers),
      )
    )
  }

  override func prepareOneTimeCodeCredentialList(
    for serviceIdentifiers: [ASCredentialServiceIdentifier]
  ) {
    show(.oneTimeCodes(identifiers: Self.identifiers(serviceIdentifiers)))
  }

  override func provideCredentialWithoutUserInteraction(
    for credentialRequest: any ASCredentialRequest
  ) {
    work?.cancel()
    work = Task { await provideSilently(credentialRequest) }
  }

  override func prepareInterfaceToProvideCredential(
    for credentialRequest: any ASCredentialRequest
  ) {
    do {
      show(.fill(try IdentityRequestReader.read(credentialRequest)))
    } catch {
      finish(failing: ProviderFailure(error, prompting: true))
    }
  }

  override func prepareInterface(
    forPasskeyRegistration registrationRequest: any ASCredentialRequest
  ) {
    do {
      let input = try IdentityRequestReader.registration(registrationRequest)
      registrationClientDataHash = input.clientDataHash
      show(.register(input))
    } catch {
      finish(failing: ProviderFailure(error, prompting: true))
    }
  }

  override func performWithoutUserInteractionIfPossible(
    passkeyRegistration registrationRequest: ASPasskeyCredentialRequest
  ) {
    finish(failing: .interactionRequired)
  }

  override func prepareInterfaceForExtensionConfiguration() {
    show(.configure)
  }

  func finish(with result: ProviderResult) {
    switch result {
    case .password:
      guard let credential = result.passwordCredential else { return finish(failing: .failed) }
      extensionContext.completeRequest(withSelectedCredential: credential)
    case .oneTimeCode:
      guard let credential = result.oneTimeCodeCredential else { return finish(failing: .failed) }
      extensionContext.completeOneTimeCodeRequest(using: credential)
    case .passkeyAssertion:
      guard let credential = result.assertionCredential else { return finish(failing: .failed) }
      extensionContext.completeAssertionRequest(using: credential)
    case .passkeyRegistration:
      guard
        let credential = result.registrationCredential(clientDataHash: registrationClientDataHash)
      else { return finish(failing: .failed) }
      extensionContext.completeRegistrationRequest(using: credential)
    case .text:
      completeText(result)
    }
  }

  func finish(failing failure: ProviderFailure) {
    extensionContext.cancelRequest(withError: failure.systemError)
  }

  func finishConfiguration() {
    extensionContext.completeExtensionConfigurationRequest()
  }

  func show(_ intent: ProviderIntent) {
    let made = makeCoordinator(interaction: .prompt)
    coordinator = made?.coordinator
    session = made?.session
    let refresh = identityRefresh(session: made?.session)
    let model = ProviderScreenModel(
      intent: intent,
      coordinator: made?.coordinator,
      responder: self,
      configure: refresh,
    )
    embed(ProviderRootView(model: model))
  }

  private func provideSilently(_ credentialRequest: any ASCredentialRequest) async {
    do {
      let read = try IdentityRequestReader.read(credentialRequest)
      guard let made = makeCoordinator(interaction: .reuseOnly(Self.silentReuseWindow)) else {
        return finish(failing: .interactionRequired)
      }
      session = made.session
      let result: ProviderResult
      do {
        try await made.coordinator.unlock(prompting: false)
        result = try await made.coordinator.provide(read.request)
      } catch {
        await made.coordinator.finish()
        throw error
      }
      await made.coordinator.finish()
      finish(with: result)
    } catch {
      log.info("silent fill needs the user")
      finish(failing: ProviderFailure(error, prompting: false))
    }
  }

  private func makeCoordinator(interaction: AuthenticationInteraction) -> MadeCoordinator? {
    do {
      let made = try ProviderEngine.make(interaction: interaction)
      return MadeCoordinator(session: made, coordinator: ProviderCoordinator(engine: made))
    } catch {
      log.error("the account could not be opened")
      return nil
    }
  }

  private func identityRefresh(session: AccountSession?) -> @Sendable () async throws -> Void {
    guard let session else {
      return {
        await IdentityRefresh.clear(SystemIdentityStore())
        throw ProviderFailure.openApp
      }
    }
    let sync = IdentitySync(source: session, store: SystemIdentityStore())
    return { _ = try await sync.refresh() }
  }

  private static func identifiers(_ services: [ASCredentialServiceIdentifier]) -> [String] {
    ServiceMatching.identifiers(for: services.map(\.service))
  }
}

private struct MadeCoordinator {
  let session: AccountSession
  let coordinator: ProviderCoordinator
}

extension ASCredentialServiceIdentifier {
  fileprivate var service: ServiceIdentifier {
    switch type {
    case .domain: ServiceIdentifier(kind: .domain, value: identifier)
    case .URL: ServiceIdentifier(kind: .url, value: identifier)
    default: ServiceIdentifier(kind: .app, value: identifier)
    }
  }
}
