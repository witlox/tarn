Feature: Network Access Supervision
  Outbound network connections from supervised processes are
  intercepted by the TarnSupervisor NE extension (NetworkFilter).
  The NE extension extracts the PID and hostname from each flow,
  checks its local supervised PID set (pushed by TarnES), and
  forwards supervised flows to TarnES via XPC for evaluation.
  TarnES applies the deny set, allow set, session cache, and
  user prompt pipeline -- the same DecisionEngine used for file
  access. All NE error paths fail-open (allow).

  Background:
    Given the TarnES and TarnSupervisor system extensions are active
    And the NE content filter is enabled
    And the whitelist contains domain "github.com"
    And the whitelist contains domain "api.anthropic.com"

  # Per-process identification

  Scenario: Flow from a supervised process is identified by audit token
    Given a supervised process opens a TLS connection to "github.com"
    When the NE filter receives handleNewFlow
    Then the source process should be identified via sourceAppAuditToken
    And audit_token_to_pid should resolve to the supervised PID
    And the local supervised PID set should contain that PID

  Scenario: Flow from an unsupervised process is allowed without XPC
    Given an unrelated process (PID 999, not supervised) opens any flow
    When the NE filter receives handleNewFlow
    Then the filter should return allow immediately
    And no XPC call to TarnES should be made

  Scenario: Flow with no audit token is allowed
    Given a flow arrives with no sourceAppAuditToken
    When the NE filter receives handleNewFlow
    Then the filter should return allow immediately

  # Hostname resolution

  Scenario: remoteHostname is used when populated
    Given a supervised process connects to "github.com" via URLSession
    When the NE filter receives handleNewFlow
    Then flow.remoteHostname should be "github.com"
    And the flow should be forwarded to TarnES with hostname "github.com"
    And the verdict should be allow (whitelisted)

  Scenario: Remote endpoint hostname is used as fallback
    Given a supervised process connects to a host where remoteHostname is nil
    And the remote endpoint hostname is "api.example.com"
    When the NE filter receives handleNewFlow
    Then "api.example.com" should be used as the hostname

  Scenario: Flow with no hostname is allowed (fail-open)
    Given a supervised process opens a flow with no remoteHostname
    And no remote endpoint is available
    When the NE filter receives handleNewFlow
    Then the filter should return allow immediately

  # Decision logic (via TarnES forwarding)

  Scenario: Allowed hostname passes silently
    Given a supervised process connects to "api.anthropic.com" via TLS
    When the flow is forwarded to TarnES for evaluation
    Then the verdict should be allow
    And no prompt should be displayed

  Scenario: Unknown hostname triggers a prompt via XPC
    Given a supervised process connects to "newdomain.example.com"
    And "newdomain.example.com" is not in the allow or deny set
    And it is not in the session cache
    When the flow is forwarded to TarnES for evaluation
    Then TarnES should send a prompt request to the CLI via XPC
    And the flow should remain paused until the user responds

  Scenario: User allows an unknown hostname for the session
    Given a paused flow for "newdomain.example.com"
    When the user selects "Allow once"
    Then TarnES should respond allow to the NE extension
    And the NE filter should resume the flow with allow
    And "newdomain.example.com" should be added to the session cache

  Scenario: User remembers an allow for a hostname
    Given a paused flow for "api.openai.com"
    When the user selects "Allow and remember"
    Then "api.openai.com" should be persisted to the whitelist via the CLI
    And the NE filter should resume the flow with allow

  Scenario: User denies an unknown hostname for the session
    Given a paused flow for "suspicious.example.com"
    When the user selects "Deny"
    Then the NE filter should resume the flow with drop
    And "suspicious.example.com" should be added to the session cache as deny

  # Async resume and deadlines

  Scenario: TCP flow can be paused for an extended user decision
    Given a TCP flow is paused waiting for the user
    When the user takes 30 seconds to respond
    Then the flow should still be alive
    And the NE filter should resume it normally

  Scenario: UDP flow auto-drops after 8 second watchdog
    Given a UDP flow is paused waiting for evaluation
    When 8 seconds elapse without a response
    Then the NE filter should auto-drop the UDP flow
    And the drop should happen before the macOS 10s deadline

  Scenario: Flow uses pauseVerdict, not synchronous wait
    Given the NE filter receives handleNewFlow for a supervised process
    Then handleNewFlow should return pauseVerdict immediately
    And handleNewFlow should NOT block on a DispatchSemaphore

  # Fail-open safety

  Scenario: XPC connection to TarnES lost
    Given the NE filter is running
    When the XPC connection to TarnES is invalidated
    Then new flows from supervised processes should be allowed
    And ESBridgeClient.evaluate should return allow

  Scenario: XPC evaluation timeout
    Given the NE filter forwards a flow to TarnES
    When TarnES does not respond within 2 seconds
    Then the NE filter should allow the flow (timeout fail-open)

  Scenario: Filter stop drains all paused flows
    Given there are 5 paused flows waiting for user decisions
    When the NE filter receives stopFilter
    Then all 5 flows should be resumed with allow
    And no flows should be left paused

  Scenario: Flow eviction at capacity
    Given the NE filter has 1000 paused flows (maximum)
    When a new flow arrives that needs to be paused
    Then the oldest paused flow should be dropped
    And the new flow should be paused normally

  # Coexistence

  Scenario: Tarn coexists with AdGuard DNS proxy
    Given AdGuard is installed as an NEDNSProxyProvider
    And tarn is installed as an NEFilterDataProvider
    When both are enabled
    Then both extensions should be active simultaneously
    And DNS resolution should go through AdGuard
    And socket flows should go through tarn

  Scenario: Tarn conflicts with another content filter
    Given another NEFilterDataProvider is already active
    When the user tries to enable tarn's filter
    Then macOS should report a conflict
