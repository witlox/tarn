Feature: Security Findings Regression
  Tests derived from Gate 1 and Gate 2 adversary review findings.
  Each scenario maps to a specific finding ID and ensures the
  fix is correct and does not regress.

  # F-04: Session Cache Key Collision Between Read and Write [CRITICAL]

  Scenario: Read-allow does not apply to write for the same path
    Given a supervised session is running
    And the user previously allowed reading "/etc/npmrc"
    When the agent tries to write to "/etc/npmrc"
    Then the user should be prompted (cache miss)
    And the session cache key for reads and writes must differ

  Scenario: Write-allow does not apply to read for the same path
    Given a supervised session is running
    And the user previously allowed writing "/etc/npmrc"
    When the agent tries to read "/etc/npmrc"
    Then the user should be prompted (cache miss)

  Scenario: Network and file cache keys never collide
    Given a file path that looks like "host:github.com"
    And a network domain "github.com"
    Then their cache keys must be different

  # F-17: Agent Readonly Paths Allow Writes via Trusted Region [MEDIUM]

  Scenario: Agent readonly path allows reads via trusted region
    Given the Claude agent profile is active
    And "~/.claude" is in the agent readonly paths
    When the agent reads "~/.claude/settings.json"
    Then the trusted region check should return true

  Scenario: Agent readonly path denies writes via trusted region
    Given the Claude agent profile is active
    And "~/.claude" is in the agent readonly paths
    When the agent writes to "~/.claude/settings.json"
    Then the trusted region check should return false
    And the write should fall through to the decision pipeline

  Scenario: Agent readwrite path allows both reads and writes
    Given the Claude agent profile is active
    And "~/.claude/projects" is in the agent readwrite paths
    When the agent writes to "~/.claude/projects/data.json"
    Then the trusted region check should return true

  # F-18: No Domain Subdomain Matching [MEDIUM]

  Scenario: Allowing a domain also allows its subdomains
    Given "github.com" is in the allowed domains
    When the agent connects to "api.github.com"
    Then the connection should be allowed (suffix match)

  Scenario: Allowing a domain does not allow unrelated domains
    Given "github.com" is in the allowed domains
    When the agent connects to "notgithub.com"
    Then the connection should prompt (no match)

  Scenario: Allowing a subdomain does not allow the parent domain
    Given "api.github.com" is in the allowed domains
    But "github.com" is NOT in the allowed domains
    When the agent connects to "github.com"
    Then the connection should prompt (no match)

  # F-19: Config.check() Directory Prefix Matching [MEDIUM]

  Scenario: Allowing a directory also allows its children
    Given the whitelist contains read-write path "~/.config/tool"
    When the agent writes to "~/.config/tool/state.json"
    Then the check should return allow

  Scenario: Allowing a directory does not allow sibling prefixes
    Given the whitelist contains read-write path "~/.config/tool"
    When the agent writes to "~/.config/toolbox/state.json"
    Then the check should return nil (unknown)

  Scenario: Readonly directory allows child reads
    Given the whitelist contains read-only path "~/.config/tool"
    When the agent reads "~/.config/tool/config.json"
    Then the check should return allow

  Scenario: Readonly directory denies child writes
    Given the whitelist contains read-only path "~/.config/tool"
    When the agent writes to "~/.config/tool/config.json"
    Then the check should return deny

  # F-26: Deny Set Missing Credential Managers [LOW]

  Scenario: 1Password CLI config is denied
    Given the base profile deny set is active
    When the agent opens "~/.config/op" for reading
    Then the access should be denied

  Scenario: password-store directory is denied
    Given the base profile deny set is active
    When the agent opens "~/.password-store" for reading
    Then the access should be denied

  Scenario: Firefox profiles are denied
    Given the base profile deny set is active
    When the agent opens "~/Library/Application Support/Firefox/Profiles" for reading
    Then the access should be denied

  # F-27: repoPath Canonicalization [LOW]

  Scenario: Repo path with ".." components is canonicalized
    Given the user starts a session with repo path "/Users/dev/repo/../../../etc"
    When the path is canonicalized
    Then the trusted region should NOT include "/etc/passwd"
    And the canonicalized path should not contain ".."

  # G2-04: Agent Readonly Paths Promptable for Write [HIGH]

  Scenario: Write to agent readonly path is denied by Config, not prompted
    Given the Claude agent profile is active
    And agent readonly paths are added to Config.readonlyPaths
    When the agent writes to "~/.claude/settings.json"
    Then Config.check() should return deny
    And the user should NOT be prompted (cannot override agent readonly)

  # G2-06: endSession Does Not Clear pendingPrompts [MEDIUM]

  Scenario: configure() clears pending prompts from previous session
    Given a session was active with cached decisions
    When configure() is called for a new session
    Then the session cache should be empty
    And the process tree should be empty
    And no pending prompts from the old session should resolve into the new cache

  # F-11: endSession Does Not Clear watchedCLIPIDs [HIGH]

  Scenario: ProcessTree removeAll clears all entries
    Given the process tree has supervised PIDs [100, 101, 102]
    When removeAll is called
    Then the tree should be empty
    And isSupervised should return false for all previous PIDs

  Scenario: ProcessTree isEmpty reflects state
    Given the process tree is empty
    Then isEmpty should return true
    When a root PID 100 is added
    Then isEmpty should return false
    When PID 100 is removed
    Then isEmpty should return true
