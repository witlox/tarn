Feature: Prompt UI
  When the monitor encounters an unknown access pattern, it
  displays an interactive prompt and collects the user's decision.

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
