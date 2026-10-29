# Try Cyberwall's local policy demo

This demo evaluates synthetic tool requests locally and exercises the adapter callback directly.
It does not intercept your Hermes session: the installed Hermes version must first add the proposed
`pre_tool_call_final` hook. Check [`hermes-contract.md`](hermes-contract.md) for the upstream status.

From the Cyberwall checkout, create a synthetic workspace and run three requests:

```bash
mkdir -p /tmp/cyberwall-demo/workspace
printf 'Synthetic demo file.\n' > /tmp/cyberwall-demo/workspace/hello.txt

# Allowed: read inside the demo workspace.
uv run cyberwall eval --policy examples/demo-policy.yaml \
  --tool read_file \
  --args '{"path":"/tmp/cyberwall-demo/workspace/hello.txt"}'

# Denied: read outside the workspace.
uv run cyberwall eval --policy examples/demo-policy.yaml \
  --tool read_file \
  --args '{"path":"/etc/hosts"}'

# Denied: unknown tool, because the policy defaults to deny.
uv run cyberwall eval --policy examples/demo-policy.yaml \
  --tool terminal \
  --args '{"command":"echo hello"}'
```

The first result is `ALLOW`; the other two are `DENY`. `cyberwall eval` only evaluates a request; it
does not run the requested tool.

The adapter records decision evidence when its final-hook callback runs inside Hermes. To inspect
the adapter behavior without enabling an unsupported hook in your Hermes profile, run the adapter
tests with `make test`. The test context provides only the registration method and calls the same
callback Cyberwall registers with Hermes.

Once Hermes supports the final hook, the plugin can be installed from the reviewed catalog using
`hermes plugins install cyberwall` and enabled with `hermes plugins enable cyberwall`. Catalog
installations are reviewed and commit-pinned; the name is not installable from the catalog yet.
