# Contributing

Every security claim must have an executable test. Keep changes small and focused, and include
positive, negative, and benign-twin tests for new enforcement behaviour. Never weaken or remove a
failing security test to make a change pass.

Read `AGENTS.md`, `docs/ARCHITECTURE.md`, and `docs/BUILD_GUIDE.md` before working. Implement one
build phase at a time. Run `make check` before submitting a change and describe what changed, what
could now be bypassed, and what was not tested.

Use synthetic data and reserved `.invalid` domains in security tests. Do not include real
credentials, malware, or third-party targets.
