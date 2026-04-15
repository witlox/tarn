Feature: Profile Composition
  Tarn uses composable security profiles layered as:
  base -> stack(s) -> agent -> user TOML -> session cache.
  Later layers extend but never remove earlier layers.
  Denied paths take precedence over all allow rules.

  # Base profile

  Scenario: Base profile provides system paths
    Given the base-macos profile is loaded
    Then read-only paths should include "/usr"
    And read-only paths should include "/System"
    And read-only paths should include "/opt/homebrew"

  Scenario: Base profile denies credential paths
    Given the base-macos profile is loaded
    Then denied paths should include "~/.aws"
    And denied paths should include "~/.gnupg"
    And denied paths should include patterns matching "~/.ssh/id_*"
    And denied paths should include "~/.kube/config"
    And denied paths should include "~/.docker/config.json"
    And denied paths should include "~/.netrc"

  Scenario: Denied paths block reads even if whitelisted elsewhere
    Given the base-macos profile denies "~/.aws"
    And a user profile grants read access to "~/.aws/config"
    When a supervised process reads "~/.aws/config"
    Then the check should return deny

  # Stack detection

  Scenario: Node stack is auto-detected from package.json
    Given the repo contains "package.json"
    When stack detection runs
    Then the stack-node profile should be activated
    And allowed domains should include "registry.npmjs.org"

  Scenario: Rust stack is auto-detected from Cargo.toml
    Given the repo contains "Cargo.toml"
    When stack detection runs
    Then the stack-rust profile should be activated
    And allowed domains should include "crates.io"

  Scenario: Python stack is auto-detected from pyproject.toml
    Given the repo contains "pyproject.toml"
    When stack detection runs
    Then the stack-python profile should be activated
    And allowed domains should include "pypi.org"

  Scenario: Go stack is auto-detected from go.mod
    Given the repo contains "go.mod"
    When stack detection runs
    Then the stack-go profile should be activated

  Scenario: Xcode stack is auto-detected from Package.swift
    Given the repo contains "Package.swift"
    When stack detection runs
    Then the stack-xcode profile should be activated

  Scenario: Multiple stacks detected simultaneously
    Given the repo contains "package.json" and "pyproject.toml"
    When stack detection runs
    Then both stack-node and stack-python should be activated

  Scenario: Explicit stack overrides auto-detection
    Given the repo contains "package.json"
    When the user passes --stack rust
    Then only stack-rust should be active
    And stack-node should not be active

  Scenario: Stack aliases are recognized
    When the user passes --stack "js,py,golang,swift"
    Then stacks node, python, go, and xcode should be active

  Scenario: Unknown stack names are ignored
    When the user passes --stack "node,cobol,rust"
    Then stacks node and rust should be active
    And no error should be raised

  # Agent profiles

  Scenario: Claude agent profile includes Anthropic API
    Given the agent is "claude"
    When profiles are composed
    Then allowed domains should include "api.anthropic.com"
    And read-only paths should include "~/.claude"

  Scenario: Codex agent profile includes OpenAI API
    Given the agent is "codex"
    When profiles are composed
    Then allowed domains should include "api.openai.com"

  Scenario: Gemini agent profile includes Google API
    Given the agent is "gemini"
    When profiles are composed
    Then allowed domains should include "generativelanguage.googleapis.com"

  Scenario: Custom agent gets minimal profile
    Given the agent is "my-custom-agent"
    When profiles are composed
    Then the agent profile should be "agent-custom"
    And no agent-specific domains should be added

  # Profile composition

  Scenario: User TOML entries layer on top of profiles
    Given the base profile and stack-node are active
    And the user TOML contains learned domain "custom.example.com"
    When profiles are composed
    Then allowed domains should include "registry.npmjs.org"
    And allowed domains should include "custom.example.com"

  Scenario: Duplicate entries across layers are deduplicated
    Given the base profile includes "/usr" as read-only
    And the user TOML also includes "/usr" as read-only
    When profiles are composed
    Then "/usr" should appear exactly once in read-only paths

  Scenario: Session summary displays active profiles
    When the CLI starts a session with agent "claude"
    Then the output should show the agent name and profile
    And the output should show detected or explicit stacks
    And the output should show entry counts for allow and deny rules

  Scenario: Agent launch command includes YOLO flags
    Given the agent is "claude"
    When tarn launches the agent
    Then the command should include "--dangerously-skip-permissions"

  Scenario: Empty repo with no stack indicators
    Given the repo contains no recognized project files
    When stack detection runs
    Then no stack profiles should be activated
    And only base and agent profiles should be active
