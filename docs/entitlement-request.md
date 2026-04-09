# Requesting Apple Restricted Entitlements

This guide covers the one-time Apple approval process needed to distribute
tarn to machines with SIP enabled. If you're only running tarn on your own
SIP-disabled machine, none of this is needed.

## Prerequisites

- Paid Apple Developer Program membership ($99/yr)
- A "Developer ID Application" certificate (created in the developer portal
  or via Xcode → Settings → Accounts → Manage Certificates)

## Step 1: Register App IDs (self-service, instant)

Go to: https://developer.apple.com/account/resources/identifiers/list

Click the **+** button to register a new App ID. Do this twice:

### App ID 1: Host app

| Field | Value |
|---|---|
| Platform | macOS |
| Type | App |
| Description | Tarn |
| Bundle ID | Explicit: `com.witlox.tarn` |

Under **Capabilities**, enable:
- **System Extension** (check the box)

Click Continue → Register.

### App ID 2: System extension

| Field | Value |
|---|---|
| Platform | macOS |
| Type | App |
| Description | Tarn Supervisor |
| Bundle ID | Explicit: `com.witlox.tarn.supervisor` |

Under **Capabilities**, enable:
- **Network Extensions** (check the box)

After checking Network Extensions, a sub-menu appears. Select:
- **Content Filter Provider**

Click Continue → Register.

## Step 2: Request Endpoint Security entitlement (Apple review)

Go to: https://developer.apple.com/contact/request/system-extension/

Fill in the form:

| Field | What to write |
|---|---|
| Company / Developer Name | *(your name or company as registered in the developer program)* |
| App Name | Tarn |
| Bundle ID | `com.witlox.tarn.supervisor` |
| System Extension Type | Endpoint Security |
| Entitlement requested | `com.apple.developer.endpoint-security.client` |
| Description of functionality | Tarn is a permission supervisor for AI coding agents on macOS. It uses the Endpoint Security framework to intercept file access (AUTH_OPEN) from a supervised process tree, check access against a user-maintained whitelist, and prompt the user to allow or deny unknown access patterns. It also subscribes to NOTIFY_FORK and NOTIFY_EXIT events to maintain the supervised process tree. The tool is agent-agnostic and supervises only the processes launched by the user through the tarn CLI. |
| Why a system extension | Endpoint Security AUTH events are only available to system extensions. The tool needs pre-execution interception of file opens to enforce the user's whitelist before the supervised process can read or write the file. |
| Distribution method | Developer ID (outside the Mac App Store) |
| Link to website or documentation | https://github.com/witlox/tarn |

Submit the form.

## Step 3: Request Network Extension content filter entitlement (Apple review)

Go to: https://developer.apple.com/contact/request/network-extension/

Fill in the form:

| Field | What to write |
|---|---|
| Company / Developer Name | *(same as above)* |
| App Name | Tarn |
| Bundle ID | `com.witlox.tarn.supervisor` |
| Network Extension Type | Content Filter Provider (System Extension) |
| Entitlement requested | `com.apple.developer.networking.networkextension` with value `content-filter-provider-systemextension` |
| Description of functionality | Tarn uses a NEFilterDataProvider to intercept outbound network connections from a supervised AI coding agent's process tree. It identifies the source process by audit token, extracts the destination hostname from the flow's remoteHostname property (with TLS SNI as a fallback), and checks the hostname against a user-maintained domain whitelist. Unknown connections are paused (pauseVerdict) while the user is prompted to allow or deny. The filter only inspects flows from the supervised process tree; all other system traffic is allowed unconditionally. |
| Why a content filter | The tool needs per-process, per-flow network access control that operates at the connect() level with hostname visibility. This is only possible via NEFilterDataProvider. DNS-level filtering (NEDNSProxyProvider) is explicitly avoided to coexist with user-installed DNS filters like AdGuard. |
| Distribution method | Developer ID (outside the Mac App Store) |
| Link to website or documentation | https://github.com/witlox/tarn |

Submit the form.

## What happens next

- Apple reviews each request independently
- Typical turnaround: 1-5 business days (can be longer)
- You'll receive an email per request: approved or follow-up questions
- Once approved, the entitlement is provisioned on your Developer ID
  certificate — you don't need to download anything new
- After both are approved, `codesign` with your Developer ID will
  accept the entitlements in `Resources/TarnSupervisor.entitlements`

## After approval

```bash
# Verify the entitlements work
make release

# If codesign succeeds, package and notarize
make dmg
NOTARIZE_KEY=~/keys/AuthKey_XXXX.p8 \
NOTARIZE_KEY_ID=XXXXXXXXXX \
NOTARIZE_ISSUER=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx \
  make notarize

# Create a GitHub release
gh release create v0.1.0 .build/release-app/Tarn-v0.1.0.dmg
```

## Common rejection reasons

- **Vague description**: Apple wants to know exactly which ES event types
  and NE provider methods you use. The descriptions above are specific.
- **No website**: having a public GitHub repo with documentation helps.
- **Wrong bundle ID**: make sure the bundle ID on the form matches the
  one in the entitlements file and the App ID registration exactly.
- **Missing App ID capabilities**: the App ID must have System Extension
  and/or Network Extensions enabled before the entitlement request.
  Register the App IDs (Step 1) before submitting the requests.
