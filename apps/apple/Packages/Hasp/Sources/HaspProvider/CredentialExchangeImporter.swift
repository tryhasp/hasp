public import Foundation
public import HaspKit

/// The receiving side of a Credential Exchange: fetch the staged CXF document, hand it to the engine,
/// and drop the copy.
public struct CredentialExchangeImporter: Sendable {
  private let source: any CredentialExchangeSource
  private let engine: any ProviderServing

  public init(source: any CredentialExchangeSource, engine: any ProviderServing) {
    self.source = source
    self.engine = engine
  }

  public func receive(token: UUID) async throws -> CredentialImportSummary {
    let document = try await source.document(token: token)
    return try await engine.importCredentialExchange(document, dryRun: false)
  }
}
