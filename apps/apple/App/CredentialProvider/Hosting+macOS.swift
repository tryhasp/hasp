#if os(macOS)
  import AppKit
  import AuthenticationServices
  import HaspProvider
  import SwiftUI

  extension CredentialProviderViewController {
    func embed(_ view: some View) {
      children.forEach { child in
        child.view.removeFromSuperview()
        child.removeFromParent()
      }
      let host = NSHostingController(rootView: view)
      addChild(host)
      host.view.frame = self.view.bounds
      host.view.autoresizingMask = [.width, .height]
      self.view.addSubview(host.view)
      preferredContentSize = NSSize(width: 360, height: 460)
    }

    func completeText(_ result: ProviderResult) {
      finish(failing: .failed)
    }
  }
#endif
