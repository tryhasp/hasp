#if os(iOS)
  import CoreTransferable
  import Foundation
  import UniformTypeIdentifiers

  struct KitDocument: Transferable {
    let data: Data

    static var transferRepresentation: some TransferRepresentation {
      DataRepresentation(exportedContentType: .pdf) { $0.data }
    }
  }
#endif
