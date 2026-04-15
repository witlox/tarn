Feature: Prompt UI
  When the DecisionEngine encounters an unknown access pattern, it
  sends a prompt request to the CLI via XPC. The CLI displays an
  interactive prompt on an alternate terminal screen, freezing the
  agent's process group to prevent output interference, then
  returns the user's decision.

  # Prompt content

  Scenario: Prompt displays file read info
    Given an unknown file read for "/etc/npmrc" by process "/usr/bin/node" PID 1234
    When the prompt is displayed
    Then it should show "File read: /etc/npmrc"
    And it should show "Process: /usr/bin/node (PID 1234)"

  Scenario: Prompt displays file write info
    Given an unknown file write for "~/.config/tool" by process "/usr/bin/tool" PID 5678
    When the prompt is displayed
    Then it should show "File write: ~/.config/tool"

  Scenario: Prompt displays network connect info
    Given an unknown network connect to "api.openai.com" by process "/usr/bin/curl" PID 9012
    When the prompt is displayed
    Then it should show "Network connect: api.openai.com"

  # User input

  Scenario: User selects allow once
    Given a prompt is displayed
    When the user enters "a"
    Then the response action should be allow
    And the response remember should be false

  Scenario: User selects allow and remember
    Given a prompt is displayed
    When the user enters "A"
    Then the response action should be allow
    And the response remember should be true

  Scenario: User selects deny
    Given a prompt is displayed
    When the user enters "d"
    Then the response action should be deny
    And the response remember should be false

  Scenario: Empty input defaults to deny
    Given a prompt is displayed
    When the user enters empty input
    Then the response action should be deny

  Scenario: Unknown input defaults to deny
    Given a prompt is displayed
    When the user enters "x"
    Then the response action should be deny

  Scenario: EOF defaults to deny
    Given a prompt is displayed
    When stdin reaches EOF
    Then the response action should be deny

  # Alternate screen buffer

  Scenario: Prompt switches to alternate screen
    Given a prompt request arrives from the ES extension
    When the CLI prepares to display the prompt
    Then the terminal should switch to the alternate screen buffer
    And the alternate screen should be cleared

  Scenario: Prompt restores main screen after response
    Given the user has responded to a prompt
    Then the terminal should switch back to the main screen buffer
    And the agent's previous output should be visible

  # Process group management

  Scenario: Agent process group stopped during prompt
    Given the agent is running with PID 100 in its own process group
    When a prompt request arrives
    Then SIGSTOP should be sent to the agent's process group (-100)
    And the agent and its children should be frozen

  Scenario: Agent process group resumed after prompt
    Given the agent's process group is stopped for a prompt
    When the user responds to the prompt
    Then SIGCONT should be sent to the agent's process group
    And the agent should resume execution

  Scenario: Terminal foreground reclaimed for prompt input
    Given the agent's process group owns the terminal foreground
    When a prompt is displayed
    Then the CLI should reclaim the terminal foreground via tcsetpgrp
    And the CLI should be able to read user input

  Scenario: Terminal foreground returned to agent after prompt
    Given the CLI has the terminal foreground for a prompt
    When the user responds
    Then the terminal foreground should be returned to the agent's process group

  # Terminal mode management

  Scenario: Terminal switched to cooked mode for prompt
    Given the agent may have set the terminal to raw mode
    When a prompt is displayed
    Then the terminal should be set to cooked mode (ICANON, ECHO)
    And the user should be able to type and see their input

  Scenario: Terminal mode restored after prompt
    Given the terminal was in raw mode before the prompt
    When the user responds and the prompt closes
    Then the terminal should be restored to its previous mode

  # Prompt serialization

  Scenario: Only one prompt displayed at a time
    Given a prompt for "/etc/npmrc" is currently displayed
    When a second prompt request for "/etc/hosts" arrives
    Then the second prompt should wait until the first is resolved
    And the user should never see two prompts simultaneously
