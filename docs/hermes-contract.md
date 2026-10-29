# Hermes integration contract

## Integration decision

Cyberwall's Hermes adapter registers `pre_tool_call_final`. This proposed upstream hook runs
after ordinary `pre_tool_call` argument modifiers and checks a detached copy of the exact
arguments Hermes is about to dispatch. It honors only `block`; approval and argument mutation are
ignored. Cyberwall treats `DENY` and `REQUIRE_APPROVAL` as blocks because its human-only approval
store and interface are not implemented yet.

The upstream contract change is proposed in [Hermes PR #146684](https://github.com/NousResearch/hermes-agent/pull/146684),
branch `cyberwall-secure-args`, currently at commit
`246165feb75c98a8c94d70c098d527eb7a77b17b`. It has not been merged or released. The plugin
cannot be enabled safely on Hermes versions that do not implement `pre_tool_call_final`; catalog
submission must wait for Hermes maintainers to accept and release that hook.

## Evidence collected

- Current upstream Hermes `main` inspected at `088f657ecf77674c7b8e2ededf4e3576d82e042c`.
- The Hermes implementation registers callbacks through `ctx.register_hook()` and exposes hook
  payload fields including `tool_name`, `args`, `task_id`, `session_id`, `tool_call_id`, `turn_id`,
  `api_request_id`, and `middleware_trace`.
- Current `pre_tool_call` allows `block`, `approve`, and `modify`; its approval path can use
  automatic approval settings, so Cyberwall does not use it for human-only approval.
- Agent inline and managed tool-executor paths call the same `_dispatch_pre_tool_call_hooks`
  helper. In the proposed change, final policy runs there after ordinary modifiers and before tool
  execution.
- The proposed final hook isolates the payload for each callback. Exceptions and timeouts produce
  a block, and wrapper-level dispatcher errors also block.
- Focused upstream verification: `tests/hermes_cli/test_plugins.py` passed (91 tests), including
  handler-not-invoked, per-callback argument isolation, and fail-closed timeout coverage.

## Not yet verified

Docker was unavailable during this work. No pinned Hermes container, live Hermes profile,
credential, model, or gateway was used. The integration tests in this repository exercise the
adapter with a fake plugin context; they do not prove installation or runtime behavior in Hermes.
The following execution surfaces remain unverified: MCP tools, child agents, `execute_code`, cron,
gateway sessions, direct `ctx.dispatch_tool`, plugin-disabled behavior, and session identity across
new/resumed sessions. These paths must remain unsupported until pinned-runtime contract tests cover
them.

The current plugin manifest declares the proposed hook, but `hermes plugins validate` cannot pass
against Hermes main until that hook is accepted upstream. No catalog entry or production-readiness
claim is warranted yet.

## References

- [Hermes plugin hooks](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/hooks.md)
- [Hermes plugin catalog submission](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/plugins/catalog-submission.md)
