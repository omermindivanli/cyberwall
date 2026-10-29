# Hermes integration contract spike

**Status:** paused before adapter code because the observed contract conflicts with the supplied
architecture and exposes a check/use gap between callbacks. This is a source inspection plus a
CLI capability check, not a completed Docker contract test.

## Environment inspected

- Installed Hermes reports `Hermes Agent v0.22.5 (2026.9.24) · stable · local`.
- Installed source revision: `bf0203a794a07aac3ff764972ab9087baa4e4f4e` (2026-10-22).
- The installed source is a local git checkout at `/Users/omermindivanli/.hermes/hermes-agent`.
- `hermes --version`, `hermes plugins --help`, `hermes plugins doctor --help`,
  `hermes plugins validate --help`, and `hermes hooks test --help` were run.
- Docker is unavailable in this environment (`docker: command not found`). No live agent or model
  was started, and no real Hermes profile or credentials were used.

## Findings against ARCHITECTURE §8.2

1. **Hook names and argument shape — source verified, registry shape partial.** The installed
   `hermes_cli.plugins.py` registers `pre_tool_call`, `post_tool_call`, and
   `transform_tool_result` in `VALID_HOOKS`. The dispatch payload includes `tool_name`, `args`,
   `task_id`, `session_id`, `tool_call_id`, `turn_id`, `api_request_id`, and
   `middleware_trace`. `PluginContext.register_hook()` is the registration API. A full snapshot of
   current built-in tool names and schemas was not taken.
2. **Execution paths — source verified for two call sites; coverage remains incomplete.** The
   installed `agent/agent_runtime_helpers.py` inline path and `agent/tool_executor.py` path both
   call `_dispatch_pre_tool_call_hooks` before dispatch. The executor path then calls the registry
   with `skip_pre_tool_call_hook=True`, avoiding its own duplicate hook call. MCP, `delegate_task`
   children, `execute_code`, cron, gateway surfaces, and direct `ctx.dispatch_tool` coverage were
   not experimentally verified. Treat them as unsupported until contract tests prove otherwise.
3. **Model invocation of slash commands — not experimentally verified.** `PluginContext.register_command`
   registers an in-session command handler, while `register_tool` registers model-callable tools.
   Source inspection did not establish that the model cannot cause command dispatch through every
   Hermes surface. Do not use slash commands for Cyberwall approval until verified.
4. **Disabled, failed, or raising plugin — source inspected; end-to-end test not run.** Plugins are
   opt-in. `_load_plugin_scoped()` records a plugin load error and lets discovery continue if
   import or `register(ctx)` fails. The `pre_tool_call` hook dispatcher converts callback exceptions
   and timeouts into a block directive. However, the outer wrappers in
   `agent_runtime_helpers._pre_tool_block_message()` and `tool_executor._pre_tool_block()` catch
   dispatcher exceptions and return no block. `safe_worker_enabled()` also returns an empty hook
   list. An external `doctor`/launcher check is still required to detect an absent guard.
5. **Argument mutation / TOCTOU — source inspection found a material risk.** `PluginDispatchMixin`
   passes the same `args` object in the callback payload and invokes multiple callbacks in sequence.
   A plugin callback can mutate that dictionary in place; a later callback can therefore see
   arguments different from those the Cyberwall callback evaluated. Hermes also accepts a
   `{"action":"modify","args":...}` directive that changes arguments before dispatch. No
   isolation or post-hook argument identity check was observed. This prevents claiming that the
   Python hook alone securely binds the checked request to the executed request.
6. **Session identity — partial source facts, lifecycle unverified.** `pre_tool_call` receives both
   `task_id` and `session_id`. Their stability across `/new`, resume, and subagents was not tested.

## Direct contradictions and decisions needed

The supplied ARCHITECTURE §8.1 says `block` is the only veto and there is no approval return. The
installed Hermes explicitly accepts `{"action":"approve","message":...,"rule_key":...}` and
routes it to a human-approval gate. The hook is therefore not limited to the documented block-only
contract. The product design must choose whether to use Hermes' native human gate (then verify its
scope, persistence, and single-use semantics) or retain a Cyberwall-owned approval flow and ignore
the native action.

The architecture requires `decide()` to check the arguments that the tool will execute. The
installed Python plugin dispatcher shares mutable arguments among callbacks, so that binding cannot
be established from one callback alone. The maintainer must decide whether Cyberwall's threat model
excludes other in-process plugins and documents this as a hard limit, or whether the project will
require an upstream Hermes change / an out-of-process enforcement boundary before claiming coverage.

Per `AGENTS.md`, implementation stopped here. Do not add Hermes plugin code until these design
decisions are resolved and the required pinned-runtime experiments can run.

## Official distribution path observed

The installed Hermes docs describe a human-reviewed catalog in `NousResearch/hermes-agent`.
Admission requires a loadable public plugin repository, an exact 40-character commit pin, and a PR
adding `plugin-catalog/<name>.yaml`; catalog CI runs `hermes plugins validate` against that pin.
There is no self-serve registration. The plugin is not ready for catalog submission: it has no
Hermes adapter and has not passed `hermes plugins validate`.

References: [Hermes plugin hook implementation](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/plugins.py),
[Hermes hook dispatch implementation](https://github.com/NousResearch/hermes-agent/blob/main/hermes_cli/plugins_dispatch.py),
[Hermes plugin catalog submission guide](https://github.com/NousResearch/hermes-agent/blob/main/website/docs/developer-guide/plugins/catalog-submission.md).
