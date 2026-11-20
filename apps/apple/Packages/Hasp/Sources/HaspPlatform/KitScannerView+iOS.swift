#if os(iOS)
  // Why: AVCaptureSession is not Sendable, and Apple requires start and stop on a background queue.
  @preconcurrency import AVFoundation
  import CoreImage
  public import Foundation
  public import SwiftUI
  import UIKit

  /// Camera preview that reports the binary payload of the first Emergency Kit QR code it sees.
  public struct KitScannerView: UIViewControllerRepresentable {
    private let onPayload: @MainActor (Data) -> Void
    private let onUnavailable: @MainActor () -> Void

    public init(
      onPayload: @escaping @MainActor (Data) -> Void,
      onUnavailable: @escaping @MainActor () -> Void,
    ) {
      self.onPayload = onPayload
      self.onUnavailable = onUnavailable
    }

    public func makeUIViewController(context: Context) -> ScannerController {
      ScannerController(onPayload: onPayload, onUnavailable: onUnavailable)
    }

    public func updateUIViewController(_ controller: ScannerController, context: Context) {}
  }

  public final class ScannerController: UIViewController {
    private let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "kr.jmo.hasp.scanner")
    private let onPayload: @MainActor (Data) -> Void
    private let onUnavailable: @MainActor () -> Void
    private var preview: AVCaptureVideoPreviewLayer?
    private let reader: CodeReader

    init(
      onPayload: @escaping @MainActor (Data) -> Void,
      onUnavailable: @escaping @MainActor () -> Void,
    ) {
      self.onPayload = onPayload
      self.onUnavailable = onUnavailable
      reader = CodeReader(onPayload: onPayload)
      super.init(nibName: nil, bundle: nil)
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) {
      preconditionFailure("not used")
    }

    public override func viewDidLoad() {
      super.viewDidLoad()
      Task { await start() }
    }

    public override func viewDidLayoutSubviews() {
      super.viewDidLayoutSubviews()
      preview?.frame = view.bounds
    }

    public override func viewDidDisappear(_ animated: Bool) {
      super.viewDidDisappear(animated)
      let session = session
      queue.async { session.stopRunning() }
    }

    private func start() async {
      guard await AVCaptureDevice.requestAccess(for: .video), configure() else {
        onUnavailable()
        return
      }
      let layer = AVCaptureVideoPreviewLayer(session: session)
      layer.videoGravity = .resizeAspectFill
      layer.frame = view.bounds
      view.layer.addSublayer(layer)
      preview = layer
      let session = session
      queue.async { session.startRunning() }
    }

    private func configure() -> Bool {
      guard let device = AVCaptureDevice.default(for: .video),
        let input = try? AVCaptureDeviceInput(device: device),
        session.canAddInput(input)
      else { return false }
      let output = AVCaptureMetadataOutput()
      session.addInput(input)
      guard session.canAddOutput(output) else { return false }
      session.addOutput(output)
      output.setMetadataObjectsDelegate(reader, queue: .main)
      output.metadataObjectTypes = [.qr]
      return true
    }
  }

  final class CodeReader: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    private let onPayload: @MainActor (Data) -> Void
    private var delivered = false

    init(onPayload: @escaping @MainActor (Data) -> Void) {
      self.onPayload = onPayload
    }

    func metadataOutput(
      _ output: AVCaptureMetadataOutput,
      didOutput objects: [AVMetadataObject],
      from connection: AVCaptureConnection,
    ) {
      guard !delivered else { return }
      for object in objects {
        guard let code = object as? AVMetadataMachineReadableCodeObject,
          let descriptor = code.descriptor as? CIQRCodeDescriptor,
          let payload = KitQRReader.byteModePayload(descriptor)
        else { continue }
        delivered = true
        let handler = onPayload
        MainActor.assumeIsolated { handler(payload) }
        return
      }
    }
  }
#endif
