Feature: Safety and Fail-Open Guarantees
  Tarn is designed to never break the user's system. The NE
  extension fails open on all error paths (allows traffic). The
  ES extension uses per-event muting to avoid system-wide
  visibility. A kill switch provides emergency recovery.

  # NE extension fail-open

  Scenario: NE filter allows traffic when ES extension is unreachable
    Given the TarnSupervisor NE extension is running
    And the XPC connection to TarnES is not established
    When a supervised process opens a network connection
    Then ESBridgeClient.evaluate should return allow
    And the flow should not be blocked

  Scenario: NE filter allows traffic on XPC timeout
    Given the NE extension forwards a flow to TarnES
    When TarnES does not respond within 2 seconds
    Then the timeout handler should fire
    And the flow should be allowed

  Scenario: NE filter allows traffic on decode failure
    Given the NE extension receives a response from TarnES
    When the response data cannot be decoded
    Then the flow should be allowed

  Scenario: NE filter drains flows on stop
    Given the NE filter has paused flows
    When stopFilter is called
    Then all paused flows should be resumed with allow
    And no traffic should be permanently blocked

  Scenario: NE filter allows flows with no audit token
    When handleNewFlow receives a flow without sourceAppAuditToken
    Then the flow should be allowed immediately

  Scenario: NE filter allows flows with no hostname
    Given a supervised process opens a flow
    And the flow has no remoteHostname and no remote endpoint
    When handleNewFlow processes the flow
    Then the flow should be allowed immediately

  Scenario: NE filter drops oldest flow when at capacity
    Given the NE filter has 1000 paused flows
    When a new supervised flow arrives
    Then the oldest paused flow should be dropped (not blocked forever)
    And the new flow should be paused for evaluation

  Scenario: UDP watchdog prevents indefinite pause
    Given a UDP flow is paused for evaluation
    When 8 seconds elapse
    Then the flow should be auto-dropped
    And this should happen before the macOS 10s auto-drop deadline

  # ES extension per-event muting

  Scenario: Non-supervised processes muted at kernel level
    Given the ES client is running
    When a non-supervised process forks a child
    Then es_mute_process_events(AUTH_OPEN) should be called for the child
    And AUTH_OPEN should never fire for that child again

  Scenario: Pre-existing processes muted on first AUTH_OPEN
    Given processes were running before the ES client started
    When a pre-existing non-supervised process triggers AUTH_OPEN
    Then it should be allowed (no supervision needed)
    And es_mute_process_events(AUTH_OPEN) should be called
    And no further AUTH_OPEN events should fire for that process

  Scenario: Supervised processes never muted for AUTH_OPEN
    Given a process is in the supervised tree
    Then es_mute_process_events should never be called for that process
    And every AUTH_OPEN from that process should reach the callback

  Scenario: NOTIFY events never muted for any process
    Given the ES client is running
    Then NOTIFY_FORK should fire for all processes (supervised and non-supervised)
    And NOTIFY_EXIT should fire for all processes

  # No system-wide visibility when idle

  Scenario: No active session means no file supervision
    Given no session is active
    And the ProcessTree is empty
    When any process opens a file
    Then the AUTH_OPEN callback should hit the fast-path allow
    And the process should be muted for future AUTH_OPEN events

  # Kill switch emergency recovery

  Scenario: Kill switch removes NE filter configuration
    When the user runs "open Tarn.app --args --kill"
    Then the NEFilterManager configuration should be removed
    And internet connectivity should be restored immediately
    And the app should exit after cleanup

  Scenario: Kill switch falls back to disable if remove fails
    Given the NE filter configuration cannot be removed
    When the kill switch runs
    Then it should attempt to disable the filter instead
    And it should report the outcome to the user

  # XPC security

  Scenario: XPC connection rejected for mismatched team ID
    Given a process with a different code signing team ID
    When it connects to the ES extension's Mach service
    Then the connection should be rejected
    And a log message should indicate team ID mismatch

  Scenario: Unsigned peer connection handled safely
    Given an unsigned process attempts to connect
    When the team ID check runs
    Then the connection should be allowed (Apple/unsigned peer)
    And the connection should still be validated for protocol conformance

  # Session teardown safety

  Scenario: CLI disconnect triggers full cleanup
    Given a supervised session is active
    When the CLI's XPC connection is invalidated
    Then the SessionCache should be cleared
    And the ProcessTree should be emptied
    And the NE extension should receive clearSupervisedPIDs
    And the DecisionEngine should be reset to defaults
    And no supervised PIDs should remain in any component

  Scenario: ES extension self-reference lost during AUTH_OPEN
    Given the ES client is processing an AUTH_OPEN event
    When the ESClient instance is deallocated (weak self is nil)
    Then the event should be allowed (fail-safe)
    And no crash should occur
