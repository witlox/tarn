Feature: File Access Supervision
  The TarnES system extension subscribes to AUTH_OPEN events via
  Endpoint Security. Supervised processes (agent + children) have
  their file opens checked against the deny set, trusted regions,
  allow set, session cache, and user prompts. Non-supervised
  processes are muted at the kernel level via es_mute_process_events
  and never trigger the AUTH_OPEN callback after first sight.

  Background:
    Given the TarnES system extension is active
    And a supervised session is running for workspace "/Users/dev/myrepo"

  # Deny set (checked first, before all other decisions)

  Scenario: Deny set blocks SSH private key access
    Given the deny set includes "~/.ssh/id_*"
    When the agent opens "~/.ssh/id_rsa" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY
    And no prompt should be displayed

  Scenario: Deny set blocks AWS credentials
    When the agent opens "~/.aws/credentials" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY
    And no prompt should be displayed

  Scenario: Deny set blocks SSH config
    When the agent opens "~/.ssh/config" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY

  Scenario: Deny set blocks GnuPG directory
    When the agent opens "~/.gnupg/secring.gpg" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY

  Scenario: Deny set blocks Docker credentials
    When the agent opens "~/.docker/config.json" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY

  Scenario: Deny set checked before trusted regions
    Given the deny set includes "~/.ssh/id_*"
    And "~/.ssh/" is in a trusted region
    When the agent opens "~/.ssh/id_ed25519" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY
    And the trusted region check should not be reached

  Scenario: Deny set checked before allow set
    Given the deny set includes "~/.aws"
    And the user profile grants read access to "~/.aws/config"
    When the agent opens "~/.aws/config" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_DENY

  # Trusted regions (workspace, system, temp)

  Scenario: Workspace path is allowed via fast path
    When the agent opens "/Users/dev/myrepo/src/main.rs" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW
    And no whitelist check should occur
    And no prompt should be displayed

  Scenario: Workspace write is allowed
    When the agent opens "/Users/dev/myrepo/src/new_file.rs" for writing
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW

  Scenario: Temp path is allowed via fast path
    When the agent opens "/tmp/build-output" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  Scenario: System library is allowed via fast path
    When the agent opens "/usr/lib/libSystem.dylib" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  # Allow set (whitelisted paths)

  Scenario: Whitelisted read-only path allows reads
    Given the whitelist contains read-only path "~/.gitconfig"
    When the agent opens "~/.gitconfig" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW

  Scenario: Whitelisted read-only path denies writes
    Given the whitelist contains read-only path "~/.gitconfig"
    When the agent opens "~/.gitconfig" for writing
    Then the user should be prompted

  Scenario: Agent config paths are allowed
    Given the agent is "claude"
    When the agent opens "~/.claude/settings.json" for reading
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW

  # Unknown paths (prompt)

  Scenario: Unknown path triggers prompt
    Given the whitelist does not contain path "/etc/npmrc"
    When the agent opens "/etc/npmrc" for reading
    Then the user should be prompted with the path and process info

  Scenario: User allows unknown path
    Given a prompt for path "/etc/npmrc"
    When the user selects "Allow once"
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW

  Scenario: User denies unknown path
    Given a prompt for path "/root/.aws/credentials"
    When the user selects "Deny"
    Then the ES extension should respond with ES_AUTH_RESULT_DENY

  # Non-supervised processes

  Scenario: Non-supervised PID is muted at kernel level
    Given PID 999 is not in the supervised process tree
    When PID 999 triggers AUTH_OPEN for the first time
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW
    And es_mute_process_events should be called for PID 999
    And subsequent AUTH_OPEN events from PID 999 should not reach the callback

  Scenario: Newly forked non-supervised child is muted immediately
    Given PID 999 is not in the supervised process tree
    When PID 999 forks child PID 1000
    Then es_mute_process_events should be called for PID 1000 in handleFork
    And PID 1000 should never trigger an AUTH_OPEN callback

  # Session cache

  Scenario: Session cache prevents re-prompting after allow
    Given the user allowed "/etc/npmrc" once (without remember)
    When the agent opens "/etc/npmrc" again
    Then the ES extension should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  Scenario: Session cache prevents re-prompting after deny
    Given the user denied "/etc/private" once (without remember)
    When the agent opens "/etc/private" again
    Then the ES extension should respond with ES_AUTH_RESULT_DENY
    And no prompt should be displayed

  Scenario: Session cache is cleared at session end
    Given the user allowed "/etc/npmrc" once (without remember)
    When the session ends and a new session starts
    Then the next open of "/etc/npmrc" should prompt again

  # Deadlines

  Scenario: AUTH response deadline is respected
    Given a prompt is displayed for an unknown path
    When the user has not responded
    Then the ES extension should not exceed the ES response deadline
    And the session cache should be consulted before prompting

  Scenario: Prompt queue overflow under deadline pressure
    Given a prompt is currently displayed and waiting for user input
    And ten more AUTH events for unknown paths are queued behind it
    When the oldest queued event approaches its ES response deadline
    Then that event should be denied to avoid killing the ES client
    And the deny should be added to the session cache to prevent retry storms

  # Error handling

  Scenario: ES client creation failure provides diagnostic
    Given the binary lacks the ES entitlement
    When the ES extension attempts to start
    Then an error should mention the entitlement requirement
    And an error should mention root privileges
