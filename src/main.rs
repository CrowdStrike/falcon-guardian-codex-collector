//! Falcon Guardian collector for Codex command hooks.

mod guardian;

use std::{env, error::Error, fmt::Display, process::ExitCode, time::Duration};

use clap::{Parser, ValueEnum};
use guardian::{BaseUrl, Function, GuardInput, GuardRequest, GuardResponse, Message, ToolCall};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

const CODEX_PROCESS_TAG: &str = "213584428666200";

#[derive(Parser)]
#[command(version, about)]
struct Args {
  /// Falcon Guardian base URL.
  #[arg(
    long,
    env = "CS_AIDR_BASE_URL",
    default_value = "https://api.crowdstrike.com/aidr/aiguard"
  )]
  base_url: BaseUrl,
  /// Seconds to wait for a verdict, including polling.
  #[arg(long, default_value_t = 30)]
  timeout: u64,
  /// What to do when Falcon Guardian can't give a verdict.
  #[arg(long, value_enum, default_value_t = FailureMode::Open)]
  failure_mode: FailureMode,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, ValueEnum)]
enum FailureMode {
  /// Let the prompt or tool call through.
  Open,
  /// Block the prompt or tool call.
  Closed,
}

impl FailureMode {
  /// The failure mode in raw `args`.
  fn from_raw_args(args: &[String]) -> Self {
    let closed = args.iter().any(|a| a == "--failure-mode=closed")
      || args
        .windows(2)
        .any(|w| w[0] == "--failure-mode" && w[1] == "closed");
    if closed { Self::Closed } else { Self::Open }
  }
}

/// One Codex hook event as read from stdin.
#[derive(Deserialize)]
#[serde(tag = "hook_event_name")]
enum Event {
  UserPromptSubmit {
    #[serde(flatten)]
    session: Session,
    prompt: String,
  },
  PreToolUse {
    #[serde(flatten)]
    session: Session,
    #[serde(flatten)]
    tool: ToolUse,
  },
  PostToolUse {
    #[serde(flatten)]
    session: Session,
    #[serde(flatten)]
    tool: ToolUse,
    tool_response: Value,
  },
  /// Events the collector doesn't guard.
  #[serde(other)]
  Unsupported,
}

impl Event {
  const fn name(&self) -> &'static str {
    match self {
      Self::UserPromptSubmit { .. } => "UserPromptSubmit",
      Self::PreToolUse { .. } => "PreToolUse",
      Self::PostToolUse { .. } => "PostToolUse",
      Self::Unsupported => "Unsupported",
    }
  }
}

#[derive(Deserialize)]
struct Session {
  session_id: String,
  cwd: String,
  model: Option<String>,
  turn_id: Option<String>,
}

#[derive(Deserialize)]
struct ToolUse {
  tool_name: String,
  tool_use_id: String,
  tool_input: Value,
}

/// Codex's `extra_info` logging schema.
#[derive(Serialize)]
struct ExtraInfo<'a> {
  app_name: &'static str,
  #[serde(skip_serializing_if = "Option::is_none")]
  user_name: Option<&'a str>,
  codex_hook_event_name: &'static str,
  codex_cwd: &'a str,
  #[serde(skip_serializing_if = "Option::is_none")]
  codex_tool_name: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  sensor_aid: Option<&'a str>,
}

fn main() -> ExitCode {
  let args = match Args::try_parse() {
    Ok(args) => args,
    Err(e) if !e.use_stderr() => e.exit(),
    Err(e) => {
      return fail(
        &e,
        FailureMode::from_raw_args(&env::args().collect::<Vec<_>>()),
      );
    }
  };
  let Some(token) = env::var("CS_AIDR_TOKEN").ok().filter(|t| !t.is_empty()) else {
    return fail(&"CS_AIDR_TOKEN is not set", args.failure_mode);
  };
  let client = guardian::Client::builder()
    .base_url(args.base_url)
    .token(token)
    .timeout(Duration::from_secs(args.timeout))
    .build();
  match run(&client) {
    Ok(Some(reply)) => {
      println!("{reply}");
      ExitCode::SUCCESS
    }
    Ok(None) => ExitCode::SUCCESS,
    Err(e) => fail(&e, args.failure_mode),
  }
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(windows)]
fn read_agent_id() -> Option<String> {
  let value = windows_registry::LOCAL_MACHINE
    .open(r"SYSTEM\CurrentControlSet\Services\CSAgent\Sim")
    .and_then(|key| key.get_value("AG"))
    .ok()?;
  if value.ty() != windows_registry::Type::Bytes {
    return None;
  }
  agent_id(&value)
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(target_os = "macos")]
fn read_agent_id() -> Option<String> {
  let output = std::process::Command::new("/Applications/Falcon.app/Contents/Resources/falconctl")
    .arg("info")
    .output()
    .ok()?;
  if !output.status.success() {
    return None;
  }
  falconctl_agent_id(&output.stdout)
}

/// The Falcon sensor's agent ID (AID), or `None` if it can't be read.
#[cfg(not(any(windows, target_os = "macos")))]
const fn read_agent_id() -> Option<String> {
  None
}

/// The AID from `falconctl info`'s plist as 32 lowercase hex digits, or `None`
/// if it's missing.
#[cfg(target_os = "macos")]
fn falconctl_agent_id(plist: &[u8]) -> Option<String> {
  #[derive(Deserialize)]
  struct Info {
    aid: String,
  }
  let Info { aid } = plist::from_bytes(plist).ok()?;
  (aid.len() == 32 && aid.bytes().all(|b| b.is_ascii_hexdigit())).then(|| aid.to_ascii_lowercase())
}

/// The AID as 32 lowercase hex digits, or `None` unless `bytes` is exactly 16 bytes.
#[cfg_attr(not(windows), allow(dead_code))]
fn agent_id(bytes: &[u8]) -> Option<String> {
  let bytes: [u8; 16] = bytes.try_into().ok()?;
  Some(format!("{:032x}", u128::from_be_bytes(bytes)))
}

/// Report `e` to Codex.
/// Open: exit 0 and show `e` as a warning, so the prompt or tool call continues.
/// Closed: exit 2 to block it, with `e` as the reason.
fn fail(e: &dyn Display, mode: FailureMode) -> ExitCode {
  let msg = format!("Falcon Guardian: {e}");
  eprintln!("{msg}");
  match mode {
    FailureMode::Open => {
      println!("{}", json!({ "systemMessage": msg }));
      ExitCode::SUCCESS
    }
    FailureMode::Closed => ExitCode::from(2),
  }
}

fn run(client: &guardian::Client) -> Result<Option<Value>> {
  let event: Event = serde_json::from_reader(std::io::stdin().lock())?;
  let user = env::var("USER").or_else(|_| env::var("USERNAME")).ok();
  let sensor_aid = read_agent_id();
  let Some(request) = guard_request(
    &event,
    user.as_deref(),
    sensor_aid.as_deref(),
    std::process::id(),
  ) else {
    return Ok(None);
  };
  reply(&event, &client.guard_chat_completions(&request)?)
}

/// The Falcon Guardian request for `event`, or `None` if the collector doesn't
/// guard it.
fn guard_request<'a>(
  event: &'a Event,
  user: Option<&'a str>,
  sensor_aid: Option<&'a str>,
  process_id: u32,
) -> Option<GuardRequest<'a, ExtraInfo<'a>>> {
  let (event_type, session, tool, messages) = match event {
    Event::UserPromptSubmit { session, prompt } => (
      "input",
      session,
      None,
      vec![Message::User {
        content: prompt.clone(),
      }],
    ),
    Event::PreToolUse { session, tool } => {
      ("tool_input", session, Some(tool), vec![tool_call(tool)])
    }
    // Falcon Guardian analyzes only messages after the last assistant message,
    // so just the tool output.
    Event::PostToolUse {
      session,
      tool,
      tool_response,
    } => (
      "tool_output",
      session,
      Some(tool),
      vec![
        tool_call(tool),
        Message::Tool {
          tool_call_id: tool.tool_use_id.clone(),
          content: match tool_response {
            Value::String(s) => s.clone(),
            other => other.to_string(),
          },
        },
      ],
    ),
    Event::Unsupported => return None,
  };
  Some(GuardRequest {
    guard_input: GuardInput { messages },
    event_type,
    model: session.model.as_deref(),
    session_id: &session.session_id,
    conversation_id: session.turn_id.as_deref(),
    user_id: user,
    agent_type: "code-assistant",
    is_agent: true,
    process_id: process_id.to_string(),
    process_tags: &[CODEX_PROCESS_TAG],
    extra_info: ExtraInfo {
      app_name: "Codex",
      user_name: user,
      codex_hook_event_name: event.name(),
      codex_cwd: &session.cwd,
      codex_tool_name: tool.map(|t| t.tool_name.as_str()),
      sensor_aid,
    },
  })
}

/// The assistant message that calls `tool`.
fn tool_call(tool: &ToolUse) -> Message {
  Message::Assistant {
    content: None,
    tool_calls: vec![ToolCall {
      id: tool.tool_use_id.clone(),
      r#type: "function".into(),
      function: Function {
        name: tool.tool_name.clone(),
        arguments: tool.tool_input.to_string(),
      },
    }],
  }
}

/// The Codex reply for the Falcon Guardian verdict on `event`, or `None` to let
/// Codex continue unchanged.
fn reply(event: &Event, res: &GuardResponse) -> Result<Option<Value>> {
  let (blocked, transformed) = (res.result.blocked, res.result.transformed);
  let reason = || {
    let summary = res.summary.as_deref().unwrap_or("blocked by policy");
    format!("Falcon Guardian: {summary}")
  };
  Ok(match event {
    _ if !blocked && !transformed => None,
    // Codex can't rewrite prompts, so a redacted prompt passes through.
    Event::UserPromptSubmit { .. } => blocked.then(|| block(&reason())),
    Event::PreToolUse { .. } if blocked => Some(json!({
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason(),
      }
    })),
    Event::PreToolUse { .. } => Some(json!({
      "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "allow",
        "updatedInput": redacted_arguments(res)?,
      }
    })),
    Event::PostToolUse { .. } if blocked => Some(block(&reason())),
    Event::PostToolUse { .. } => Some(block(&redacted_output(res)?)),
    Event::Unsupported => None,
  })
}

fn block(reason: &str) -> Value {
  json!({ "decision": "block", "reason": reason })
}

/// The last `guard_output` message.
fn redacted(res: &GuardResponse) -> Result<Message> {
  let GuardInput { mut messages } = res.result.guard_output()?;
  Ok(messages.pop().ok_or("guard_output has no messages")?)
}

fn redacted_arguments(res: &GuardResponse) -> Result<Value> {
  let Message::Assistant { tool_calls, .. } = redacted(res)? else {
    return Err("guard_output doesn't end with a tool call".into());
  };
  let call = tool_calls
    .into_iter()
    .next()
    .ok_or("guard_output has no tool call")?;
  Ok(serde_json::from_str(&call.function.arguments)?)
}

fn redacted_output(res: &GuardResponse) -> Result<String> {
  match redacted(res)? {
    Message::Tool { content, .. } => Ok(content),
    _ => Err("guard_output doesn't end with a tool message".into()),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  fn hook(fields: Value) -> Event {
    let mut payload = json!({
      "session_id": "s1",
      "transcript_path": null,
      "cwd": "/w",
      "model": "gpt-5.6-luna",
      "turn_id": "t1",
      "permission_mode": "default",
    });
    let Value::Object(fields) = fields else {
      panic!("hook fields must be an object");
    };
    payload.as_object_mut().unwrap().extend(fields);
    serde_json::from_value(payload).unwrap()
  }

  fn prompt() -> Event {
    hook(json!({ "hook_event_name": "UserPromptSubmit", "prompt": "my SSN is 900-12-3456" }))
  }

  fn pre_tool_use() -> Event {
    hook(json!({
      "hook_event_name": "PreToolUse",
      "tool_name": "apply_patch",
      "tool_use_id": "call_1",
      "tool_input": { "command": "*** Begin Patch\n+900-12-3456\n*** End Patch" },
    }))
  }

  fn post_tool_use() -> Event {
    hook(json!({
      "hook_event_name": "PostToolUse",
      "tool_name": "Bash",
      "tool_use_id": "call_1",
      "tool_input": { "command": "echo 900-12-3456" },
      "tool_response": "900-12-3456\r\n",
    }))
  }

  fn request(event: &Event) -> Value {
    let req = guard_request(
      event,
      Some("dennis"),
      Some("d4208f3f3cf544f196bfe612aa8035fe"),
      4242,
    );
    serde_json::to_value(req.unwrap()).unwrap()
  }

  fn verdict(fields: Value) -> GuardResponse {
    let mut res = json!({ "status": "Success", "summary": "SSN was detected and blocked." });
    res["result"] = fields;
    serde_json::from_value(res).unwrap()
  }

  fn clean() -> GuardResponse {
    verdict(json!({ "blocked": false, "transformed": false }))
  }

  fn blocked() -> GuardResponse {
    verdict(json!({ "blocked": true, "transformed": false }))
  }

  fn transformed(messages: &Value) -> GuardResponse {
    verdict(
      json!({ "blocked": false, "transformed": true, "guard_output": { "messages": messages } }),
    )
  }

  #[test]
  fn failure_mode_survives_usage_errors() {
    let mode = |args: &[&str]| {
      FailureMode::from_raw_args(&args.iter().map(ToString::to_string).collect::<Vec<_>>())
    };
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode", "closed"]),
      FailureMode::Closed
    );
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode=closed"]),
      FailureMode::Closed
    );
    assert_eq!(
      mode(&["c", "--bogus", "--failure-mode", "open"]),
      FailureMode::Open
    );
    assert_eq!(mode(&["c", "--bogus"]), FailureMode::Open);
  }

  #[test]
  fn agent_id_is_16_bytes_as_lowercase_hex() {
    let ag = [
      0xD4, 0x20, 0x8F, 0x3F, 0x3C, 0xF5, 0x44, 0xF1, 0x96, 0xBF, 0xE6, 0x12, 0xAA, 0x80, 0x35,
      0xFE,
    ];
    assert_eq!(
      agent_id(&ag).as_deref(),
      Some("d4208f3f3cf544f196bfe612aa8035fe")
    );
    assert_eq!(agent_id(&ag[..15]), None);
    assert_eq!(agent_id(&[]), None);
  }

  #[test]
  #[cfg(target_os = "macos")]
  fn falconctl_agent_id_is_lowercase_hex() {
    let plist = |dict: &str| {
      format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    {dict}
    <key>cid</key>
    <string>6CB9530D078E415F96CE34BE06631A37</string>
    <key>sensor_loaded</key>
    <true/>
</dict>
</plist>"#
      )
    };
    let aid = |aid: &str| {
      falconctl_agent_id(plist(&format!("<key>aid</key><string>{aid}</string>")).as_bytes())
    };
    assert_eq!(
      aid("3B6BB4B2F4104BA5A689B67D3CAA24FF").as_deref(),
      Some("3b6bb4b2f4104ba5a689b67d3caa24ff")
    );
    assert_eq!(aid(""), None);
    assert_eq!(aid("3B6BB4B2F4104BA5A689B67D3CAA24F"), None);
    assert_eq!(falconctl_agent_id(plist("").as_bytes()), None);
    assert_eq!(falconctl_agent_id(b"not a plist"), None);
  }

  #[test]
  fn prompt_is_sent_as_input() {
    assert_eq!(
      request(&prompt()),
      json!({
        "guard_input": { "messages": [{ "role": "user", "content": "my SSN is 900-12-3456" }] },
        "event_type": "input",
        "model": "gpt-5.6-luna",
        "session_id": "s1",
        "conversation_id": "t1",
        "user_id": "dennis",
        "agent_type": "code-assistant",
        "is_agent": true,
        "process_id": "4242",
        "process_tags": ["213584428666200"],
        "extra_info": {
          "app_name": "Codex",
          "user_name": "dennis",
          "codex_hook_event_name": "UserPromptSubmit",
          "codex_cwd": "/w",
          "sensor_aid": "d4208f3f3cf544f196bfe612aa8035fe",
        },
      })
    );
  }

  #[test]
  fn tool_input_is_sent_as_json_encoded_arguments() {
    let req = request(&pre_tool_use());
    assert_eq!(req["event_type"], "tool_input");
    assert_eq!(req["extra_info"]["codex_tool_name"], "apply_patch");
    assert_eq!(
      req["guard_input"]["messages"],
      json!([{
        "role": "assistant",
        "content": null,
        "tool_calls": [{
          "id": "call_1",
          "type": "function",
          "function": {
            "name": "apply_patch",
            "arguments": r#"{"command":"*** Begin Patch\n+900-12-3456\n*** End Patch"}"#,
          },
        }],
      }])
    );
  }

  #[test]
  fn tool_output_string_is_sent_verbatim() {
    let req = request(&post_tool_use());
    assert_eq!(req["event_type"], "tool_output");
    assert_eq!(
      req["guard_input"]["messages"][1],
      json!({ "role": "tool", "tool_call_id": "call_1", "content": "900-12-3456\r\n" })
    );
  }

  #[test]
  fn unsupported_events_are_not_guarded() {
    let stop = hook(json!({ "hook_event_name": "Stop", "stop_hook_active": false }));
    assert!(guard_request(&stop, None, None, 4242).is_none());
    assert_eq!(reply(&stop, &blocked()).unwrap(), None);
  }

  #[test]
  fn clean_verdicts_continue() {
    for event in [prompt(), pre_tool_use(), post_tool_use()] {
      assert_eq!(reply(&event, &clean()).unwrap(), None);
    }
  }

  #[test]
  fn blocked_prompt_is_blocked() {
    assert_eq!(
      reply(&prompt(), &blocked()).unwrap(),
      Some(
        json!({ "decision": "block", "reason": "Falcon Guardian: SSN was detected and blocked." })
      )
    );
  }

  #[test]
  fn redacted_prompt_passes_through() {
    let res = transformed(&json!([{ "role": "user", "content": "my SSN is <US_SSN>" }]));
    assert_eq!(reply(&prompt(), &res).unwrap(), None);
  }

  #[test]
  fn blocked_tool_input_is_denied() {
    assert_eq!(
      reply(&pre_tool_use(), &blocked()).unwrap(),
      Some(json!({
        "hookSpecificOutput": {
          "hookEventName": "PreToolUse",
          "permissionDecision": "deny",
          "permissionDecisionReason": "Falcon Guardian: SSN was detected and blocked.",
        }
      }))
    );
  }

  #[test]
  fn redacted_tool_input_rewrites_the_call() {
    let res = transformed(&json!([{
      "role": "assistant",
      "content": null,
      "tool_calls": [{
        "id": "call_1",
        "type": "function",
        "function": {
          "name": "apply_patch",
          "arguments": r#"{"command":"*** Begin Patch\n+<US_SSN>\n*** End Patch"}"#,
        },
      }],
    }]));
    assert_eq!(
      reply(&pre_tool_use(), &res).unwrap(),
      Some(json!({
        "hookSpecificOutput": {
          "hookEventName": "PreToolUse",
          "permissionDecision": "allow",
          "updatedInput": { "command": "*** Begin Patch\n+<US_SSN>\n*** End Patch" },
        }
      }))
    );
  }

  #[test]
  fn blocked_tool_output_is_replaced_by_the_reason() {
    assert_eq!(
      reply(&post_tool_use(), &blocked()).unwrap(),
      Some(
        json!({ "decision": "block", "reason": "Falcon Guardian: SSN was detected and blocked." })
      )
    );
  }

  #[test]
  fn redacted_tool_output_replaces_the_output() {
    let res = transformed(&json!([
      { "role": "assistant", "content": null, "tool_calls": [] },
      { "role": "tool", "tool_call_id": "call_1", "content": "<US_SSN>\r\n" },
    ]));
    assert_eq!(
      reply(&post_tool_use(), &res).unwrap(),
      Some(json!({ "decision": "block", "reason": "<US_SSN>\r\n" }))
    );
  }

  #[test]
  fn transformed_verdict_without_guard_output_is_an_error() {
    let res = verdict(json!({ "blocked": false, "transformed": true }));
    assert!(reply(&pre_tool_use(), &res).is_err());
    assert!(reply(&post_tool_use(), &res).is_err());
  }
}
