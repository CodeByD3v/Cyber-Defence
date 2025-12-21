# Frontend hooks (no layout changes)

The existing dashboard currently runs commands locally. To connect it to the backend, you only need to:

1) Open a WebSocket to the backend
2) Send commands as `{ "type": "command", "command": "/replay slammer.pcap" }`
3) Handle backend events (`system_status`, `stats_update`, `flow`, `attack_alert`, `command_output`)

## WebSocket

Connect:

- URL: `ws://127.0.0.1:8765/ws`

### Send command

```js
ws.send(JSON.stringify({ type: 'command', command: '/status' }));
```

### Incoming messages

All messages are JSON strings.

#### `system_status`

Emitted on connect and after every command.

```json
{
  "type": "system_status",
  "timestamp": "...",
  "started_at": "...",
  "zeek": { "running": false, "mode": "stopped" },
  "replay": { "running": false },
  "ml": { "running": true, "model": "...pkl", "threshold": 0.8, "window_seconds": 60 },
  "telemetry": { "last_packet_ts": null, "last_alert_ts": null }
}
```

#### `command_output`

Line-by-line output for commands and process stdout.

```json
{
  "type": "command_output",
  "timestamp": "...",
  "stream": "command",
  "level": "stdout",
  "line": "Zeek started (live mode)."
}
```

#### `flow`

Raw Zeek JSON-lines record (UI monitor should render these as-is):

```json
{
  "type": "flow",
  "timestamp": "...",
  "log": "conn",
  "src": "10.0.0.5",
  "dst": "8.8.8.8",
  "record": { "ts": 1730000000.0, "id.orig_h": "10.0.0.5", "id.resp_h": "8.8.8.8", "proto": "tcp" }
}
```

#### `attack_alert`

Behavioral verdict:

```json
{
  "type": "attack_alert",
  "timestamp": "...",
  "attack": "backdoor_like_c2",
  "confidence": 0.86,
  "src": "10.0.0.5",
  "dst": "8.8.8.8",
  "evidence": ["Periodic DNS"],
  "ml": { "malicious_score": 0.91, "model_mode": "binary", "predicted_label": "malicious", "raw_class": null }
}
```

## Minimal JS wiring idea

Where your existing `processCommand(input)` currently calls `commands[cmd].execute(args)`, replace (or branch) so that SOC commands are forwarded to the backend:

```js
// Pseudocode: do not change layout; just replace local execution for SOC commands
const ws = new WebSocket('ws://127.0.0.1:8765/ws');

ws.onmessage = (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.type === 'command_output' && msg.stream === 'command') addCommandLine(msg.line);
  if (msg.type === 'command_output' && msg.stream !== 'command') addProcessingLine(`[${msg.stream}] ${msg.line}`);
  if (msg.type === 'flow') addMonitorLine(JSON.stringify(msg.record));
  if (msg.type === 'attack_alert') addAlertLine(`${msg.attack} ${msg.confidence}`);
  if (msg.type === 'stats_update') updateStatsFromBackend(msg.stats);
  if (msg.type === 'system_status') updateStatusFromBackend(msg);
};

function sendSocCommand(line) {
  ws.send(JSON.stringify({ type: 'command', command: line }));
}
```
