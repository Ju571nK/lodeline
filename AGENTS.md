# AGENTS.md

## GitHub Issue Triage

- Conserve tokens when inspecting GitHub issues: request only the fields and number of results needed for the task, then summarize rather than reproducing full issue bodies.

## Generative AI Compatibility Gate

- Before implementing any issue tied to a generative AI product, verify that product's current behavior using official documentation, release notes, and the locally installed version when available.
- Record changes to configuration paths and precedence, permission or approval modes, hook events and payloads, MCP/tool behavior, unattended modes, and platform-specific behavior before changing code.
- Distinguish documented behavior from hardware-verified behavior. Do not remove compatibility gates or enable enforcement from documentation alone when the repository records conflicting measurements.
- Keep research scoped per product and date-stamped so later issue work can reuse it without repeating full discovery.

## Lodeline Proxy Agent Workflow

For Lodeline Proxy work, read [the specification entry point](docs/specs/lodeline-proxy/README.md),
[agent roles and operating rules](docs/specs/lodeline-proxy/agents/README.md), and
[current execution status](docs/specs/lodeline-proxy/execution.md) before starting.

The orchestrating assistant (not a delegate that was handed one task) delegates scoped research, coding, review and verification, starts workers only for concrete tasks, assigns one writer per file, links results to requirement and acceptance IDs, keeps `execution.md` current and reports integrated results to the user. Keep implementation, review and hardware verification apart. Read [`apps/manager/AGENTS.md`](apps/manager/AGENTS.md) and [`apps/manager/README.md`](apps/manager/README.md) before assigning work on the fleet console.
