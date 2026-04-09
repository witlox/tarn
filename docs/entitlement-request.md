# Entitlements and Signing Setup

This guide covers the setup needed to distribute tarn to machines with
SIP enabled. If you're only running tarn on your own SIP-disabled
machine, none of this is needed — `make install-dev` works without
any Apple provisioning.

## What's restricted and what isn't

| Entitlement | Restricted? | Process |
|---|---|---|
| Network Extension content filter (`content-filter-provider-systemextension`) | **No** | Enable capability on App ID, create provisioning profile, sign |
| Endpoint Security (`endpoint-security.client`) | **Yes** | Submit request form, wait for Apple review (1-5 business days) |

The NE content filter entitlement was restricted before November 2016
but hasn't been since. Per Quinn "The Eskimo!" on the Apple Developer
Forums: "Any developer can now use the Network Extension provider
capability like they would any other capability." The only NE
entitlements that still require Apple approval are Hotspot Helper and
App Push Provider — content filter is not one of them.

## Prerequisites

- Paid Apple Developer Program membership ($99/yr)
- A "Developer ID Application" certificate (created in the developer
  portal or via Xcode → Settings → Accounts → Manage Certificates)

## Step 1: Register App IDs (self-service, instant)

Go to: https://developer.apple.com/account/resources/identifiers/list

Click **+** to register a new App ID. Do this twice:

### App ID 1: Host app

| Field | Value |
|---|---|
| Platform | macOS |
| Type | App |
| Description | Tarn |
| Bundle ID | Explicit: `com.witlox.tarn` |

Under **Capabilities**, enable:
- **System Extension**

Click Continue → Register.

### App ID 2: System extension

| Field | Value |
|---|---|
| Platform | macOS |
| Type | App |
| Description | Tarn Supervisor |
| Bundle ID | Explicit: `com.witlox.tarn.supervisor` |

Under **Capabilities**, enable:
- **Network Extensions**
- **System Extension**

Click Continue → Register.

## Step 2: Create provisioning profiles (self-service, instant)

Go to: https://developer.apple.com/account/resources/profiles/list

Click **+** to create a new profile. Do this twice:

### Profile 1: Host app

| Field | Value |
|---|---|
| Type | Developer ID |
| App ID | Tarn (`com.witlox.tarn`) |
| Certificate | your Developer ID Application certificate |

Download the `.provisionprofile` file.

### Profile 2: System extension

| Field | Value |
|---|---|
| Type | Developer ID |
| App ID | Tarn Supervisor (`com.witlox.tarn.supervisor`) |
| Certificate | your Developer ID Application certificate |

Download the `.provisionprofile` file. This profile automatically
includes the `content-filter-provider-systemextension` entitlement
because you enabled Network Extensions on the App ID.

Install both profiles by double-clicking them (they go into
`~/Library/MobileDevice/Provisioning Profiles/`).

## Step 3: Request Endpoint Security entitlement (Apple review)

This is the only restricted entitlement. The NE content filter does
NOT need a separate request.

Go to: https://developer.apple.com/contact/request/system-extension/

| Field | What to write |
|---|---|
| Company / Developer Name | *(your name as registered in the developer program)* |
| App Name | Tarn |
| Bundle ID | `com.witlox.tarn.supervisor` |
| System Extension Type | Endpoint Security |
| Entitlement requested | `com.apple.developer.endpoint-security.client` |
| Description | Tarn is a permission supervisor for AI coding agents on macOS. It uses Endpoint Security AUTH_OPEN events to intercept file access from a supervised process tree, checks each access against a user-maintained whitelist and a compiled-in credential deny list, and prompts the user to allow or deny. It subscribes to NOTIFY_FORK and NOTIFY_EXIT to track the agent's subprocess tree. Only the agent's processes are supervised; all other system processes are allowed unconditionally. |
| Why a system extension | Endpoint Security AUTH events require a system extension. The tool needs pre-execution interception of file opens to enforce the whitelist before the supervised process can read or write the file. |
| Distribution method | Developer ID (outside the Mac App Store) |
| URL | https://github.com/witlox/tarn |

Submit and wait for Apple's email (typically 1-5 business days).

## After ES approval

Once Apple grants the Endpoint Security entitlement:

```bash
make release    # xcodebuild with Developer ID signing
make dmg        # package into drag-to-install DMG
make notarize   # submit to Apple for notarization (uses API key)

gh release create v0.1.0 .build/release-app/Tarn-v0.1.0.dmg
```

## While waiting for ES approval

The NE content filter works without the ES entitlement. You can build,
sign, and test the network supervision side immediately. File
supervision (ES) will fail to initialize until the entitlement is
granted — the supervisor logs a clear error and continues with
network-only supervision.

For full development (both ES + NE), use a SIP-disabled machine:
`make install-dev` — no entitlements or provisioning needed at all.
