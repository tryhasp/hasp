public import Foundation
import Darwin

/// Heap storage that zeroes itself on `deinit`. It never copies.
public struct SecretBuffer: ~Copyable {
  private let storage: UnsafeMutableRawBufferPointer

  public init(copying bytes: some Collection<UInt8>) {
    storage = .allocate(byteCount: max(bytes.count, 1), alignment: 1)
    storage.copyBytes(from: bytes)
    count = bytes.count
  }

  public let count: Int

  public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
    try body(UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(storage)[..<count]))
  }

  deinit {
    memset_s(storage.baseAddress, storage.count, 0, storage.count)
    storage.deallocate()
  }
}

/// A secret handed out by the engine for one use. The bytes are zeroed when the last reference goes.
public final class RevealedSecret: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
  private let buffer: SecretBuffer

  init(_ data: Data) {
    buffer = SecretBuffer(copying: data)
  }

  public init(text: String) {
    buffer = SecretBuffer(copying: Array(text.utf8))
  }

  public var description: String { "<redacted>" }
  public var debugDescription: String { "<redacted>" }

  public func text() -> String {
    buffer.withUnsafeBytes { String(decoding: $0, as: UTF8.self) }
  }

  public func data() -> Data {
    buffer.withUnsafeBytes { Data($0) }
  }
}

// Why: the storage is immutable after init and never shared mutably.
extension SecretBuffer: @unchecked Sendable {}
