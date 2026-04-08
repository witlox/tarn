.PHONY: all build test clean release

DEVELOPER_DIR ?= /Applications/Xcode.app/Contents/Developer
export DEVELOPER_DIR

all: build

# Build TarnCore library and the CLI via SPM.
# The supervisor and host app are built by xcodebuild (see `release`).
build:
	swift build

# Run TarnCore unit tests via SPM.
test:
	swift test

clean:
	swift package clean
	rm -rf .build DerivedData

# Build the signed and notarized Tarn.app via xcodebuild.
# Requires the Xcode project (Tarn.xcodeproj) and Developer ID
# certificate with ES + NE entitlements provisioned.
release:
	@echo "TODO: xcodebuild -project Tarn.xcodeproj -scheme Tarn -configuration Release"
	@echo "TODO: notarytool submit Tarn.app"
