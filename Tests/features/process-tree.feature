Feature: Process Tree Tracking
  The TarnES extension tracks the agent's process subtree using
  NOTIFY_FORK and NOTIFY_EXIT events. The agent root PID is
  registered via the suspended-spawn protocol. Child PIDs are
  auto-tracked when a supervised parent forks. Supervised PIDs
  are pushed to the NE extension for network flow filtering.

  # Agent root PID registration (suspended spawn)

  Scenario: Agent root PID registered via suspended spawn
    Given the CLI calls prepareAgentLaunch with its own PID
    And the CLI spawns the agent with POSIX_SPAWN_START_SUSPENDED
    When NOTIFY_FORK fires for the CLI's fork
    Then the child PID should be added to the supervised tree as a root
    And es_mute_process_events should NOT be called for the child
    And the child PID should be pushed to the NE extension

  Scenario: Agent root PID confirmed after spawn
    Given the agent root PID was registered via NOTIFY_FORK
    When the CLI calls confirmAgentPID with the agent's PID
    Then the ProcessTree should confirm the entry
    And no error should be returned

  Scenario: SIGCONT starts the agent after registration
    Given the agent PID is in the supervised tree
    When the CLI sends SIGCONT to the agent
    Then the agent's first file open should be intercepted by AUTH_OPEN

  Scenario: Invalid PID rejected by confirmAgentPID
    When the CLI calls confirmAgentPID with PID -1
    Then an error should be returned
    And the ProcessTree should not be modified

  Scenario: Dead PID rejected by confirmAgentPID
    When the CLI calls confirmAgentPID with a PID that does not exist
    Then an error should be returned

  # Child process tracking

  Scenario: Child of agent is supervised
    Given PID 100 is the agent root
    When PID 100 forks child PID 101
    Then PID 101 should be in the supervised tree
    And es_mute_process_events should NOT be called for PID 101
    And PID 101 should be pushed to the NE extension

  Scenario: Grandchild of agent is supervised
    Given PID 100 is the agent root
    And PID 100 forked PID 101
    When PID 101 forks child PID 102
    Then PID 102 should be in the supervised tree
    And PID 102 should be pushed to the NE extension

  Scenario: Non-supervised child is muted immediately
    Given PID 999 is not in the supervised tree
    When PID 999 forks child PID 1000
    Then PID 1000 should not be in the supervised tree
    And es_mute_process_events(AUTH_OPEN) should be called for PID 1000

  Scenario: Unrelated process is not supervised
    Given PID 100 is the agent root
    Then PID 999 should not be in the supervised tree

  # Process exit

  Scenario: Exited supervised process is removed from tree
    Given PID 100 is the agent root
    And PID 100 forked PID 101
    When PID 101 exits
    Then PID 101 should not be in the supervised tree
    And PID 100 should still be in the supervised tree
    And PID 101 removal should be pushed to the NE extension

  Scenario: Agent root exit clears the tree
    Given PID 100 is the agent root and the only supervised process
    When PID 100 exits
    Then the supervised tree should be empty

  Scenario: Exec retains supervised status
    Given PID 101 is in the supervised tree
    When PID 101 calls exec to become a different binary
    Then PID 101 should still be in the supervised tree

  # NE extension PID synchronization

  Scenario: Supervised PID pushed to NE on fork
    Given PID 100 is supervised
    When PID 100 forks child PID 101
    Then ESXPCService should call notifyNE(addPID: 101)
    And the NE extension's local supervised set should contain PID 101

  Scenario: Supervised PID removed from NE on exit
    Given PID 101 is supervised
    When PID 101 exits
    Then ESXPCService should call notifyNE(removePID: 101)
    And the NE extension's local supervised set should not contain PID 101

  Scenario: Session teardown clears NE supervised set
    When the CLI disconnects
    Then ESXPCService should call notifyNEClearAll
    And the NE extension's local supervised set should be empty
    And the ProcessTree should be empty
    And the SessionCache should be empty
