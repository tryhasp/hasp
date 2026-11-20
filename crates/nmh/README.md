# hasp-nmh

Native-messaging host for the Hasp desktop app (protocol 7.2 C and 7.16).

    extension --stdio--> hasp-nmh --unix socket--> app (hasp_nmh::desktop)

- The host speaks length-prefixed JSON (`framing`, `message`). It relays only `enrol_request` and `unlock` upward and `enrol_reply`, `unlock_reply`, `lock`, `error` downward.
- Chromium and Firefox start the host. Safari does not: its web extension talks to the Safari handler inside the app, which builds a `desktop::Session` over its own `Link` with `Browser::Safari`. The same `message` types apply; being inside the app bundle is the verification.
- `manifest` writes the four host manifests under `~/Library/Application Support`.
- Build with `HASP_TEAM_ID` set, and with feature `dev-extension` only for development builds.
