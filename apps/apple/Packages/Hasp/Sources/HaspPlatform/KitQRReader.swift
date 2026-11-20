import CoreImage
public import Foundation
import ImageIO
import Vision

/// Reads the binary payload of an Emergency Kit QR code from an image file.
public enum KitQRReader {
  public static func payload(inImageAt url: URL) -> Data? {
    guard let source = CGImageSourceCreateWithURL(url as CFURL, nil) else { return nil }
    return payload(in: source)
  }

  public static func payload(inImageData data: Data) -> Data? {
    guard let source = CGImageSourceCreateWithData(data as CFData, nil) else { return nil }
    return payload(in: source)
  }

  private static func payload(in source: CGImageSource) -> Data? {
    guard let image = CGImageSourceCreateImageAtIndex(source, 0, nil) else { return nil }
    let request = VNDetectBarcodesRequest()
    request.symbologies = [.qr]
    do {
      try VNImageRequestHandler(cgImage: image).perform([request])
    } catch {
      return nil
    }
    for code in request.results ?? [] {
      if let descriptor = code.barcodeDescriptor as? CIQRCodeDescriptor,
        let bytes = byteModePayload(descriptor)
      {
        return bytes
      }
    }
    return nil
  }

  static func byteModePayload(_ descriptor: CIQRCodeDescriptor) -> Data? {
    let bits = Bits(descriptor.errorCorrectedPayload)
    guard bits.read(0, 4) == 0b0100 else { return nil }
    let countBits = descriptor.symbolVersion < 10 ? 8 : 16
    guard let count = bits.read(4, countBits) else { return nil }
    var out = Data()
    for index in 0..<count {
      guard let byte = bits.read(4 + countBits + index * 8, 8) else { return nil }
      out.append(UInt8(byte))
    }
    return out
  }

  private struct Bits {
    let data: Data

    init(_ data: Data) {
      self.data = data
    }

    func read(_ offset: Int, _ count: Int) -> Int? {
      guard offset + count <= data.count * 8 else { return nil }
      var value = 0
      for position in offset..<(offset + count) {
        let byte = data[data.startIndex + position / 8]
        value = (value << 1) | Int((byte >> (7 - UInt8(position % 8))) & 1)
      }
      return value
    }
  }
}
