Feature: Endpoint Security Monitor
  The Monitor subscribes to ES AUTH events, applies fast paths
  and whitelist checks, and delegates unknown access to the prompt.

  Scenario: Workspace path is allowed via fast path
    Given the workspace is "/Users/dev/myrepo"
    When a supervised process opens "/Users/dev/myrepo/src/main.rs"
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW
    And no whitelist check should occur
    And no prompt should be displayed

  Scenario: Temp path is allowed via fast path
    When a supervised process opens "/tmp/build-output"
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  Scenario: System path is allowed via fast path
    When a supervised process opens "/usr/lib/libSystem.dylib"
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  Scenario: Whitelisted path is allowed
    Given the whitelist contains read-only path "~/.gitconfig"
    When a supervised process opens "~/.gitconfig" for reading
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW

  Scenario: Unknown path triggers prompt
    Given the whitelist does not contain path "/etc/npmrc"
    When a supervised process opens "/etc/npmrc" for reading
    Then the user should be prompted with the path and process info

  Scenario: User allows unknown path
    Given a prompt for path "/etc/npmrc"
    When the user selects "Allow once"
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW

  Scenario: User denies unknown path
    Given a prompt for path "/root/.aws/credentials"
    When the user selects "Deny"
    Then the monitor should respond with ES_AUTH_RESULT_DENY

  Scenario: Unsupervised PID is allowed unconditionally
    Given PID 999 is not in the supervised process tree
    When PID 999 opens any file
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW
    And no whitelist check should occur

  Scenario: Session cache prevents re-prompting after allow
    Given the user allowed "/etc/npmrc" once (without remember)
    When the same supervised process opens "/etc/npmrc" again
    Then the monitor should respond with ES_AUTH_RESULT_ALLOW
    And no prompt should be displayed

  Scenario: Session cache prevents re-prompting after deny
    Given the user denied "/etc/private" once (without remember)
    When the same supervised process opens "/etc/private" again
    Then the monitor should respond with ES_AUTH_RESULT_DENY
    And no prompt should be displayed

  Scenario: Session cache is cleared at session end
    Given the user allowed "/etc/npmrc" once (without remember)
    When tarn exits and a new session starts
    Then the next open of "/etc/npmrc" should prompt again

  Scenario: ES client creation failure provides diagnostic
    Given the binary lacks the ES entitlement
    When the monitor attempts to start
    Then an error should mention the entitlement requirement
    And an error should mention root privileges

  Scenario: AUTH response deadline is respected
    Given a prompt is displayed for an unknown path
    When the user has not responded
    Then the monitor should not exceed the ES response deadline
    And the session cache should be consulted before prompting

  Scenario: Prompt queue overflow under deadline pressure
    Given a prompt is currently displayed and waiting for user input
    And ten more AUTH events for unknown paths are queued behind it
    When the oldest queued event approaches its ES response deadline
    Then that event should be denied to avoid killing the ES client
    And the deny should be added to the session cache to prevent retry storms
    And the user should see a one-line note in the terminal about the deadline-driven deny
