import HaspKit

enum SidebarSelection: Hashable {
  case all
  case favourites
  case vault(VaultID)
  case category(String)
  case archive
  case trash
  case watchtower(WatchKind?)
}
