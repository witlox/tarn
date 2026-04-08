Feature: Whitelist Profile Management
  The global whitelist profile controls which paths and network
  domains are accessible by supervised agent processes. It persists
  across sessions and grows as the user approves access patterns.

  Background:
    Given a default profile exists at "~/Library/Application Support/tarn/profile.toml"

  Scenario: Default profile contains expected read-only paths
    When I load the profile
    Then the read-only paths should include "~/.gitconfig"
    And the read-only paths should include "~/.ssh/known_hosts"

  Scenario: Default profile contains expected network domains
    When I load the profile
    Then the allowed domains should include "github.com"
    And the allowed domains should include "api.anthropic.com"

  Scenario: Default entries are not marked as learned
    When I load the profile
    Then no entries should be marked as learned

  Scenario: Whitelisted read-only path allows reads
    Given the profile contains read-only path "~/.gitconfig"
    When a supervised process opens "~/.gitconfig" for reading
    Then the check should return allow

  Scenario: Whitelisted read-only path denies writes
    Given the profile contains read-only path "~/.gitconfig"
    When a supervised process opens "~/.gitconfig" for writing
    Then the check should return deny

  Scenario: Read-write path allows both reads and writes
    Given the profile contains read-write path "~/.tool/state"
    When a supervised process opens "~/.tool/state" for writing
    Then the check should return allow

  Scenario: Unknown path returns nil for prompt
    Given the profile does not contain path "~/.aws/credentials"
    When a supervised process opens "~/.aws/credentials" for reading
    Then the check should return nil
    And the user should be prompted

  Scenario: Approving a path with remember adds learned entry
    Given the profile does not contain path "~/.npmrc"
    When the user approves read access to "~/.npmrc" with remember
    Then the read-only paths should include "~/.npmrc"
    And the entry "~/.npmrc" should be marked as learned

  Scenario: Approving a domain with remember adds learned entry
    Given the profile does not contain domain "api.openai.com"
    When the user approves network access to "api.openai.com" with remember
    Then the allowed domains should include "api.openai.com"
    And the domain entry should be marked as learned

  Scenario: Duplicate additions are ignored
    Given the profile contains read-only path "~/.gitconfig"
    When I add read-only path "~/.gitconfig"
    Then "~/.gitconfig" should appear exactly once

  Scenario: Profile reset removes only learned entries
    Given the profile contains learned entry "~/.npmrc"
    And the profile contains default entry "~/.gitconfig"
    When I reset the profile
    Then the read-only paths should not include "~/.npmrc"
    And the read-only paths should include "~/.gitconfig"

  Scenario: Profile is created with defaults if missing
    Given no profile file exists
    When I load the profile
    Then a default profile should be created at "~/Library/Application Support/tarn/profile.toml"

  Scenario: Atomic write prevents corruption
    Given a profile with learned entries exists
    When a write is interrupted mid-save
    Then the profile on disk should be either the old or new version
    And the profile should never be partially written

  Scenario: Allow and remember persists before responding to the kernel
    Given an unknown path "/etc/foo" is being prompted
    When the user selects "Allow and remember"
    Then the new entry should be written to the profile on disk
    And only after the write succeeds should the kernel see ES_AUTH_RESULT_ALLOW

  Scenario: Allow and remember degrades gracefully on disk write failure
    Given the profile directory is read-only
    And an unknown path "/etc/foo" is being prompted
    When the user selects "Allow and remember"
    Then the access should still be allowed for the current request
    And the entry should be added to the session cache only
    And a warning should be printed naming the disk failure
    And the user should be told the entry will not survive the session

  Scenario: Corrupt profile TOML refuses to start
    Given the profile file contains malformed TOML
    When tarn run starts
    Then the CLI should exit with a clear error
    And the error should name the line and column of the parse failure
    And the profile file should not be auto-overwritten

  Scenario: Profile is owned by SUDO_USER, not root
    Given tarn is launched via sudo by user "alice"
    When tarn materializes the default profile
    Then the profile file should be owned by "alice"
    And the profile path should resolve under alice's home directory
