Feature: CLI Commands
  The tarn CLI provides commands for launching supervised agent
  sessions and managing the global whitelist profile.

  Scenario: tarn run with default agent
    When I run "sudo tarn run /tmp/myrepo"
    Then the agent should default to "claude"
    And the profile should default to "~/Library/Application Support/tarn/profile.toml"

  Scenario: tarn run with explicit agent
    When I run "sudo tarn run /tmp/myrepo --agent codex"
    Then the agent should be set to "codex"

  Scenario: tarn run with custom profile path
    When I run "sudo tarn run /tmp/myrepo --profile /tmp/custom.toml"
    Then the profile should be loaded from "/tmp/custom.toml"

  Scenario: tarn run launches agent in YOLO mode
    When I run "sudo tarn run /tmp/myrepo --agent claude"
    Then the agent should be launched with "--dangerously-skip-permissions"

  Scenario: tarn run fails for nonexistent repo
    When I run "sudo tarn run /does/not/exist"
    Then the CLI should exit with a nonzero status
    And the error should mention the path

  Scenario: tarn run requires root
    Given the user is not root
    When I run "tarn run /tmp/myrepo"
    Then the ES client creation should fail
    And the error should mention root privileges

  Scenario: tarn profile show displays all sections
    Given a profile with defaults and learned entries
    When I run "tarn profile show"
    Then the output should include a "Read-only paths" section
    And the output should include a "Read-write paths" section
    And the output should include an "Allowed network domains" section

  Scenario: tarn profile show tags learned entries
    Given a profile with learned entry "~/.npmrc"
    When I run "tarn profile show"
    Then the output should show "~/.npmrc (learned)"

  Scenario: tarn profile reset with confirmation
    Given a profile with learned entries
    When I run "tarn profile reset"
    Then the CLI should ask "Continue? [y/N]"
    And if I respond "y" the learned entries should be removed

  Scenario: tarn profile reset with --force skips confirmation
    When I run "tarn profile reset --force"
    Then the learned entries should be removed
    And no confirmation prompt should appear

  Scenario: tarn with no subcommand shows help
    When I run "tarn" with no arguments
    Then the output should include usage information
    And the output should list available subcommands

  Scenario: tarn exits with agent exit code
    Given the agent exits with status 42
    Then tarn should exit with status 42

  Scenario: tarn refuses to run without SUDO_USER
    Given the user is logged in directly as root
    And SUDO_USER is unset in the environment
    When I run "tarn run /tmp/myrepo"
    Then the CLI should exit with a clear error
    And the error should explain that tarn must be invoked via sudo from a normal user account
    And no profile should be created under "/var/root/Library/Application Support/tarn/"

  Scenario: tarn refuses to start a second concurrent session
    Given a tarn session is already running for the current user
    And its lock file is at "~/Library/Application Support/tarn/tarn.lock"
    When I run "sudo tarn run /tmp/another-repo"
    Then the second invocation should exit with a clear error
    And the error should point at the existing lock file

  Scenario: Stale lock files are removed on startup
    Given a stale lock file exists at "~/Library/Application Support/tarn/tarn.lock"
    And the PID recorded in the lock file is no longer alive
    When I run "sudo tarn run /tmp/myrepo"
    Then tarn should remove the stale lock and proceed
    And the new session should write its own PID to the lock file

  Scenario: tarn profile reset is idempotent on a clean profile
    Given a profile with no learned entries
    When I run "tarn profile reset --force"
    Then the CLI should exit successfully
    And the output should note that there were no learned entries to remove

  Scenario: tarn profile show on a missing profile
    Given the profile file does not exist
    When I run "tarn profile show"
    Then tarn should materialize the default profile
    And the output should display the default entries

  Scenario: tarn profile reset on a missing profile
    Given the profile file does not exist
    When I run "tarn profile reset --force"
    Then tarn should materialize the default profile
    And the output should note that the profile is at defaults
