.PHONY: all build test lint clean release notarize

DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer
export DEVELOPER_DIR

# Set TEAM_ID via environment or command line:
#   make install-dev TEAM_ID=XXXXXXXXXX
TEAM_ID ?=

VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "dev")
BUILD_DIR := .build/release-app
DMG_NAME := Tarn-$(VERSION).dmg

all: build

# Build TarnCore library and the CLI via SPM.
build:
	swift build

# Run TarnCore unit tests via SPM.
test:
	swift test

# Run SwiftLint.
lint:
	swiftlint lint --strict

clean:
	swift package clean
	rm -rf .build DerivedData $(BUILD_DIR)

# Regenerate the Xcode project from project.yml.
project:
	xcodegen generate

# Build for local development. Uses automatic signing — Xcode picks
# up the provisioning profiles you installed from the developer portal.
# On a SIP-disabled machine, the system extension loads without
# notarization. On a normal machine, you need `make release` instead.
install-dev: project
	@test -n "$(TEAM_ID)" || (echo "Set TEAM_ID: make install-dev TEAM_ID=XXXXXXXXXX" && exit 1)
	mkdir -p $(BUILD_DIR)
	xcodebuild build \
		-project Tarn.xcodeproj \
		-scheme TarnApp \
		-configuration Debug \
		-derivedDataPath $(BUILD_DIR)/DerivedData \
		DEVELOPMENT_TEAM=$(TEAM_ID) \
		CODE_SIGN_IDENTITY="Developer ID Application"
	$(eval APP := $(shell find $(BUILD_DIR)/DerivedData -name "Tarn.app" -type d | head -1))
	@echo ""
	@echo "Built: $(APP)"
	@echo "To activate the system extension on a SIP-disabled machine:"
	@echo "  sudo systemextensionsctl developer on"
	@echo "  open $(APP)"

# Build the signed Tarn.app for distribution via xcodebuild.
# Prerequisites:
#   - Developer ID Application certificate in keychain
#   - Apple-granted entitlements (only needed for SIP-enabled machines)
release: project
	@test -n "$(TEAM_ID)" || (echo "Set TEAM_ID: make release TEAM_ID=XXXXXXXXXX" && exit 1)
	mkdir -p $(BUILD_DIR)
	xcodebuild build \
		-project Tarn.xcodeproj \
		-scheme TarnApp \
		-configuration Release \
		-derivedDataPath $(BUILD_DIR)/DerivedData \
		DEVELOPMENT_TEAM=$(TEAM_ID) \
		CODE_SIGN_IDENTITY="Developer ID Application" \
		OTHER_CODE_SIGN_FLAGS="--timestamp --options runtime" \
		CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO
	$(eval APP := $(shell find $(BUILD_DIR)/DerivedData -name "Tarn.app" -type d | head -1))
	@echo "Built: $(APP)"
	@codesign -dvv "$(APP)" 2>&1 | head -3
	@echo ""
	@echo "Create DMG with: make dmg"
	@echo "Then notarize with: make notarize"

# Package the built app into a DMG.
dmg: $(BUILD_DIR)/DerivedData
	$(eval APP := $(shell find $(BUILD_DIR)/DerivedData -name "Tarn.app" -type d | head -1))
	mkdir -p $(BUILD_DIR)/dmg-stage
	cp -R "$(APP)" $(BUILD_DIR)/dmg-stage/
	ln -sf /Applications $(BUILD_DIR)/dmg-stage/Applications
	hdiutil create \
		-volname "Tarn" \
		-srcfolder $(BUILD_DIR)/dmg-stage \
		-ov -format UDZO \
		$(BUILD_DIR)/$(DMG_NAME)
	codesign --sign "Developer ID Application" --timestamp $(BUILD_DIR)/$(DMG_NAME)
	@echo ""
	@echo "DMG: $(BUILD_DIR)/$(DMG_NAME)"
	@echo "Notarize with: make notarize"

# Notarize the DMG using an App Store Connect API key.
# Set these environment variables (or pass on the command line):
#   NOTARIZE_KEY      path to the .p8 API key file
#   NOTARIZE_KEY_ID   the Key ID from App Store Connect
#   NOTARIZE_ISSUER   the Issuer ID from App Store Connect
#
# Generate the key at:
#   https://appstoreconnect.apple.com/access/integrations/api
#   → Keys → App Store Connect API → Generate
notarize:
	@test -n "$(NOTARIZE_KEY)" || (echo "Set NOTARIZE_KEY to the path of your .p8 API key" && exit 1)
	@test -n "$(NOTARIZE_KEY_ID)" || (echo "Set NOTARIZE_KEY_ID" && exit 1)
	@test -n "$(NOTARIZE_ISSUER)" || (echo "Set NOTARIZE_ISSUER" && exit 1)
	xcrun notarytool submit $(BUILD_DIR)/$(DMG_NAME) \
		--key "$(NOTARIZE_KEY)" \
		--key-id "$(NOTARIZE_KEY_ID)" \
		--issuer "$(NOTARIZE_ISSUER)" \
		--wait
	xcrun stapler staple $(BUILD_DIR)/$(DMG_NAME)
	@echo ""
	@echo "Notarized and stapled: $(BUILD_DIR)/$(DMG_NAME)"
	@echo "Upload with: gh release create v$(VERSION) $(BUILD_DIR)/$(DMG_NAME)"
