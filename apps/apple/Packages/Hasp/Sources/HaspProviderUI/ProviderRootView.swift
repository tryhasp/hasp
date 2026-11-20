import HaspDesign
public import SwiftUI

public struct ProviderRootView: View {
  @State private var model: ProviderScreenModel

  public init(model: ProviderScreenModel) {
    _model = State(initialValue: model)
  }

  public var body: some View {
    NavigationStack {
      content
        .navigationTitle(title)
        .toolbar {
          ToolbarItem(placement: .cancellationAction) {
            Button("provider.cancel") { Task { await model.cancel() } }
              .accessibilityIdentifier("provider.cancel")
          }
        }
    }
    .task { await model.start() }
    .frame(minWidth: 320, minHeight: 360)
  }

  @ViewBuilder
  private var content: some View {
    switch model.phase {
    case .unlocking: ProviderStatusView(key: "provider.unlocking", showsProgress: true)
    case .working: ProviderStatusView(key: "provider.working", showsProgress: true)
    case .list: ProviderListView(model: model)
    case .confirm: ProviderConfirmView(model: model)
    case .failed(let failure): ProviderFailureView(model: model, failure: failure)
    }
  }

  private var title: LocalizedStringKey {
    switch model.intent {
    case .passwords, .fill, .passkeys: "provider.title.passwords"
    case .oneTimeCodes: "provider.title.codes"
    case .text: "provider.title.text"
    case .register: "provider.title.save"
    case .configure: "provider.title.configure"
    }
  }
}
