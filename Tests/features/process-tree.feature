Feature: Process Tree Tracking
  Tarn supervises only the agent's subprocess tree. All other
  system processes are allowed unconditionally.

  Scenario: Agent root PID is supervised
    Given tarn launches agent with PID 100
    Then PID 100 should be in the supervised tree

  Scenario: Child of agent is supervised
    Given PID 100 is the agent root
    When PID 100 forks child PID 101
    Then PID 101 should be in the supervised tree

  Scenario: Grandchild of agent is supervised
    Given PID 100 is the agent root
    And PID 100 forked PID 101
    When PID 101 forks child PID 102
    Then PID 102 should be in the supervised tree

  Scenario: Unrelated process is not supervised
    Given PID 100 is the agent root
    Then PID 999 should not be in the supervised tree

  Scenario: Child of unrelated process is not supervised
    Given PID 100 is the agent root
    When PID 999 forks child PID 1000
    Then PID 1000 should not be in the supervised tree

  Scenario: Exited process is removed from tree
    Given PID 100 is the agent root
    And PID 100 forked PID 101
    When PID 101 exits
    Then PID 101 should not be in the supervised tree
    And PID 100 should still be in the supervised tree

  Scenario: Exec retains supervised status
    Given PID 101 is in the supervised tree
    When PID 101 calls exec to become a different binary
    Then PID 101 should still be in the supervised tree

  Scenario: AUTH event for unsupervised PID is allowed immediately
    Given PID 999 is not in the supervised tree
    When an AUTH_OPEN event fires for PID 999
    Then the monitor should respond ALLOW without checking the whitelist

  Scenario: Empty tree after all processes exit
    Given PID 100 is the agent root
    When PID 100 exits
    Then the supervised tree should be empty
