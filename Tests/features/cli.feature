Feature: CLI Commands
  The tarn CLI provides commands for launching supervised agent
  sessions and managing the global whitelist profile. The CLI
  is unprivileged (no sudo) and connects to the TarnES system
  extension via XPC for supervision.

  # tarn run

  Scenario: tarn run with default agent
    When I run "tarn run /tmp/myrepo"
    Then the agent should default to "claude"
    And the profile should default to "~/Library/Application Support/tarn/profile.toml"

  Scenario: tarn run with explicit agent
    When I run "tarn run /tmp/myrepo --agent codex"
    Then the agent should be set to "codex"

  Scenario: tarn run with custom profile path
    When I run "tarn run /tmp/myrepo --profile /tmp/custom.toml"
    Then the profile should be loaded from "/tmp/custom.toml"

  Scenario: tarn run with resume flag
    When I run "tarn run /tmp/myrepo --agent claude --resume"
    Then the agent launch command should include "--resume"

  Scenario: tarn run fails for nonexistent repo
    When I run "tarn run /does/not/exist"
    Then the CLI should exit with a nonzero status
    And the error should mention the path

  Scenario: tarn run connects to TarnES extension
    When I run "tarn run /tmp/myrepo"
    Then the CLI should connect to the TarnES Mach service
    And the connection should use kTarnESMachServiceName

  Scenario: tarn run fails when extension not active
    Given the TarnES system extension is not running
    When I run "tarn run /tmp/myrepo"
    Then the CLI should print a message about the system extension
    And the CLI should suggest opening Tarn.app

  # Session lifecycle

  Scenario: Session start configures DecisionEngine
    When the CLI starts a session with agent "claude" and repo "/tmp/myrepo"
    Then the ES extension should configure DecisionEngine with the composed profile
    And the DecisionEngine should have the repo path as workspace
    And the DecisionEngine should have agent-specific allowed paths

  Scenario: Session start returns summary
    When the CLI starts a session
    Then the response should include a session ID
    And the response should include detected stack names
    And the response should include allow and deny entry counts

  Scenario: Session end clears state
    Given a session is active
    When the CLI calls endSession
    Then the DecisionEngine session cache should be cleared
    And the ProcessTree should be empty

  Scenario: CLI disconnect triggers full cleanup
    Given a session is active with supervised processes
    When the CLI's XPC connection is invalidated
    Then the session cache should be cleared
    And the ProcessTree should be emptied
    And the NE extension should receive clearSupervisedPIDs
    And the DecisionEngine should be reset to defaults

  # Agent launch (suspended spawn)

  Scenario: CLI registers before spawning agent
    When the CLI launches an agent
    Then prepareAgentLaunch should be called BEFORE posix_spawn
    And the CLI's own PID should be passed as cliPID

  Scenario: Agent spawned in its own process group
    When the CLI spawns the agent
    Then the agent should have POSIX_SPAWN_SETPGROUP set
    And the agent's PGID should equal its own PID

  Scenario: Agent PID confirmed after spawn
    Given the CLI has spawned the agent with PID 100
    Then confirmAgentPID should be called with PID 100

  Scenario: Agent gets terminal foreground
    When the CLI spawns the agent
    Then tcsetpgrp should give the agent's process group the terminal foreground

  Scenario: tarn exits with agent exit code
    Given the agent exits with status 42
    Then tarn should exit with status 42

  # Environment scrubbing

  Scenario: Sensitive environment variables removed before agent launch
    Given the environment contains AWS_SECRET_ACCESS_KEY
    When the CLI launches the agent
    Then the agent's environment should not contain AWS_SECRET_ACCESS_KEY

  Scenario: GitHub tokens removed from environment
    Given the environment contains GITHUB_TOKEN and GH_TOKEN
    When the CLI launches the agent
    Then the agent's environment should not contain GITHUB_TOKEN
    And the agent's environment should not contain GH_TOKEN

  Scenario: SSH auth socket removed from environment
    Given the environment contains SSH_AUTH_SOCK
    When the CLI launches the agent
    Then the agent's environment should not contain SSH_AUTH_SOCK

  Scenario: Pattern-matched sensitive variables removed
    Given the environment contains MY_SECRET_KEY and DATABASE_PASSWORD
    When the CLI launches the agent
    Then the agent's environment should not contain MY_SECRET_KEY
    And the agent's environment should not contain DATABASE_PASSWORD

  Scenario: Non-sensitive variables preserved
    Given the environment contains PATH and HOME and TERM
    When the CLI launches the agent
    Then the agent's environment should contain PATH
    And the agent's environment should contain HOME
    And the agent's environment should contain TERM

  # Kill switch

  Scenario: Kill switch removes NE filter config
    When I run "open Tarn.app --args --kill"
    Then the NE filter configuration should be removed
    And internet connectivity should be restored

  # Profile management

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

  # Lock file

  Scenario: tarn refuses to start a second concurrent session
    Given a tarn session is already running for the current user
    And its lock file is at "~/Library/Application Support/tarn/tarn.lock"
    When I run "tarn run /tmp/another-repo"
    Then the second invocation should exit with a clear error

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
