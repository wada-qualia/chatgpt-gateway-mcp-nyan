# Synthetic chat-context isolation demo

This is a **standalone synthetic illustration**, not production evidence. It models one shared in-memory infrastructure surface with two chat contexts and exactly three context-bound resource families:

- `CommandSession`
- `Monitoring`
- `FileChange`

Both contexts use the same synthetic principal, client and backend. Each context can list only its own three resources, and an exact lookup of the other context's command session fails closed with HTTP `404` and `Command session not found`.

The example deliberately does **not** claim that every Gateway resource family is isolated. Production claims require separate runtime evidence.

## Safety boundary

The demo:

- uses only the Python standard library;
- binds to `127.0.0.1` only;
- keeps deterministic state in memory;
- has no credentials or configuration files;
- performs no shell, SSH, Docker or MCP calls;
- makes no outbound network requests;
- does not import or start the Gateway application.

## Run

Python 3.12+ is recommended to match the public Gateway project baseline.

```bash
python3 examples/chat-context-isolation/server.py --self-test
python3 examples/chat-context-isolation/server.py --port 8765
```

Open `http://127.0.0.1:8765/` in a browser. The complete isolation result is visible without interaction.

The read-only JSON view is available at:

```text
GET /api/demo
GET /api/contexts/context-a/resources
GET /api/contexts/context-b/resources
GET /api/contexts/context-a/sessions/session-a
GET /api/contexts/context-b/sessions/session-b
```

The two fail-closed cross-context examples are:

```text
GET /api/contexts/context-a/sessions/session-b  -> 404 Command session not found
GET /api/contexts/context-b/sessions/session-a  -> 404 Command session not found
```

## Test

```bash
python3 -m unittest -v examples/chat-context-isolation/test_demo.py
```

The tests cover deterministic resource ownership, symmetric cross-context lookup failure, the explicit synthetic/not-production-evidence marker, and the loopback HTTP surface.
