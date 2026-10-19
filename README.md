# falcon-guardian-codex-collector

Falcon Guardian collector for Codex hooks.

## Usage

Add the following to [a `hooks.json`](https://learn.chatgpt.com/docs/hooks#where-codex-looks-for-hooks)
file:

```json
{
  "hooks": {
    "UserPromptSubmit": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/falcon-guardian-codex-collector"
          }
        ]
      }
    ],
    "PreToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/falcon-guardian-codex-collector"
          }
        ]
      }
    ],
    "PostToolUse": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "/path/to/falcon-guardian-codex-collector"
          }
        ]
      }
    ]
  }
}
```

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--token` | `CS_AIDR_TOKEN` | required |
| `--base-url` | `CS_AIDR_BASE_URL` | `https://api.crowdstrike.com/aidr/aiguard` |
| `--timeout <secs>` | | `30` |
| `--failure-mode <open\|closed>` | | `open` |
