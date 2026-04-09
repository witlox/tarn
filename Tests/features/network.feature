Feature: Network Access Control
  Outbound network connections from supervised processes are
  intercepted by tarn's NEFilterDataProvider, which runs inside the
  tarn supervisor system extension. The filter identifies the source
  process by its BSM audit token, extracts the destination hostname
  (from remoteHostname or via TLS SNI), and matches it against the
  user's allow/deny set. Novel flows are paused while the user is
  prompted via XPC.

  Background:
    Given the tarn system extension is active and the filter is enabled
    And the whitelist contains domain "github.com"
    And the whitelist contains domain "api.anthropic.com"

  # Per-process identification

  Scenario: Flow from a supervised process is identified by audit token
    Given a supervised process opens a TLS connection to "github.com"
    When the filter receives handleNewFlow
    Then the source process should be identified via sourceAppAuditToken
    And audit_token_to_pid should resolve to the supervised PID
    And the supervised process tree lookup should succeed

  Scenario: Flow from an unsupervised process is allowed unconditionally
    Given an unrelated process (PID 999, not in the supervised tree) opens any flow
    When the filter receives handleNewFlow
    Then the filter should return allowVerdict immediately
    And no further checks should be performed

  # Hostname resolution paths

  Scenario: remoteHostname is used when populated
    Given a supervised process initiates a connection via URLSession to "github.com"
    When the filter receives handleNewFlow
    Then flow.remoteHostname should be "github.com"
    And the filter should match against the allow set using "github.com"
    And the verdict should be allowVerdict

  Scenario: TLS SNI is used when remoteHostname is nil
    Given a supervised process opens a raw TCP socket to a github.com IP
    And flow.remoteHostname is nil
    When the filter receives handleNewFlow
    Then the filter should return filterDataVerdict requesting outbound peek of 1024 bytes
    And the next callback should parse the TLS ClientHello SNI
    And the SNI should be "github.com"
    And the filter should match against the allow set using "github.com"
    And the final verdict should be allowVerdict

  Scenario: Raw IP is used when no hostname is available
    Given a supervised process opens a non-TLS plaintext connection to "203.0.113.42"
    When the filter receives handleNewFlow
    Then the filter should use "203.0.113.42" as the destination identifier
    And the user should be prompted with the raw IP

  # Decision logic

  Scenario: Allowed hostname passes silently
    Given a supervised process connects to "api.anthropic.com" via TLS
    When the filter receives handleNewFlow
    Then the verdict should be allowVerdict
    And no prompt should be displayed

  Scenario: Denied hostname is dropped silently
    Given a deny rule matches "tracker.example.com"
    And a supervised process connects to "tracker.example.com"
    When the filter receives handleNewFlow
    Then the verdict should be dropVerdict
    And no prompt should be displayed

  Scenario: Unknown hostname triggers a prompt via XPC
    Given a supervised process connects to "newdomain.example.com"
    And "newdomain.example.com" is not in the allow or deny set
    And it is not in the session cache
    When the filter receives handleNewFlow
    Then the verdict should be pauseVerdict
    And the supervisor should send a PromptRequest to the CLI via XPC
    And the supervisor should wait for a PromptResponse

  Scenario: User allows an unknown hostname for the session
    Given a paused flow for "newdomain.example.com"
    When the user selects "Allow once"
    Then the supervisor should call resumeFlow with allowVerdict
    And "newdomain.example.com" should be added to the session cache as allow
    And subsequent flows to "newdomain.example.com" should not re-prompt

  Scenario: User remembers an allow for a hostname
    Given a paused flow for "api.openai.com"
    When the user selects "Allow and remember"
    Then "api.openai.com" should be persisted to the whitelist
    And only after the disk write succeeds should resumeFlow be called with allowVerdict
    And subsequent sessions should treat "api.openai.com" as allowed without prompting

  Scenario: User denies an unknown hostname for the session
    Given a paused flow for "suspicious.example.com"
    When the user selects "Deny"
    Then the supervisor should call resumeFlow with dropVerdict
    And "suspicious.example.com" should be added to the session cache as deny
    And subsequent flows to "suspicious.example.com" should not re-prompt

  Scenario: Allow and remember is hidden for raw-IP prompts
    Given a paused flow with no hostname, only the raw IP "203.0.113.42"
    When the user is prompted
    Then the prompt should offer "Allow once" and "Deny" but not "Allow and remember"
    And the prompt should explain that the whitelist accepts hostnames only

  # Async resume and deadlines

  Scenario: TCP flow can be paused for an extended user decision
    Given a TCP flow is paused waiting for the user
    When the user takes 30 seconds to respond
    Then the flow should still be alive
    And the supervisor should resume it normally

  Scenario: UDP flow auto-denies near the system deadline
    Given a UDP flow is paused waiting for the user
    When the prompt has been outstanding for 8 seconds
    Then the supervisor should auto-deny the flow before macOS auto-drops it
    And the deny should be added to the session cache

  Scenario: Filter does not use synchronous semaphore wait
    Given the filter receives handleNewFlow for an unknown hostname
    Then handleNewFlow should return pauseVerdict immediately
    And handleNewFlow should NOT block on a DispatchSemaphore
    And the filter thread pool should remain available for other flows

  # Coexistence

  Scenario: AdGuard NXDOMAIN response prevents the flow from ever firing
    Given AdGuard's DNS proxy returns NXDOMAIN for "blocked.example.com"
    And "blocked.example.com" is in tarn's whitelist
    When a supervised process tries to connect to "blocked.example.com"
    Then no flow should be created (the agent never gets an IP)
    And tarn's filter should not receive handleNewFlow for this connection

  Scenario: tarn coexists with AdGuard's DNS proxy
    Given AdGuard is installed as an NEDNSProxyProvider
    And tarn is installed as an NEFilterDataProvider
    When tarn's filter is enabled
    Then both extensions should be active simultaneously
    And neither should interfere with the other
    And DNS resolution should still go through AdGuard

  Scenario: tarn refuses to coexist with another content filter
    Given another NEFilterDataProvider (e.g., Little Snitch, LuLu) is already active
    When the user tries to enable tarn's filter
    Then macOS should report a conflict
    And tarn should document this in the README and surface it in the activation flow
