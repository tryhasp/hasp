#if os(iOS)
  import AuthenticationServices
  import HaspProvider
  import SwiftUI
  import UIKit

  extension CredentialProviderViewController {
    func embed(_ view: some View) {
      children.forEach { child in
        child.willMove(toParent: nil)
        child.view.removeFromSuperview()
        child.removeFromParent()
      }
      let host = UIHostingController(rootView: view)
      addChild(host)
      host.view.frame = self.view.bounds
      host.view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
      self.view.addSubview(host.view)
      host.didMove(toParent: self)
    }

    func completeText(_ result: ProviderResult) {
      guard let text = result.insertedText else { return finish(failing: .failed) }
      extensionContext.completeRequest(withTextToInsert: text)
    }

    override func prepareInterfaceForUserChoosingTextToInsert() {
      show(.text)
    }
  }
#endif
