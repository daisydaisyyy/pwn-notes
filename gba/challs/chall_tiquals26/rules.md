# Synthesizer

## Wire protocol

On connect, the server sends a round object:

```json
{
  "type": "round",
  "index": 1,
  "input": {
    "regs": [0, 1, 2, 3, 4, 5, 6, 7],
    "mem": "00112233..."
  },
  "target": {
    "regs": [123, null, null, null, 456, 789, null, null],
    "mem": "001122...",
    "focus": {
      "regs": [0, 4, 5],
      "mem_ranges": []
    }
  },
  "constraints": {
    "allowed_opcodes": [0, 6, 7, 8, 9, 10, 11, 12],
    "max_program_bytes": 12,
    "max_steps": 4096
  }
}
```

- `input.regs` &mdash; eight 64-bit registers (unsigned).
- `input.mem` &mdash; 256 bytes, hex encoded.
- `target.focus.regs` &mdash; register indices that must match the
  corresponding entries in `target.regs` exactly.
- `target.focus.mem_ranges` &mdash; inclusive byte ranges that must match
  exactly.
- `constraints.allowed_opcodes` &mdash; the only macro-opcode bytes you may
  use in this round.
- `constraints.max_program_bytes` &mdash; the submitted bytecode may not
  exceed this length in bytes.
- `constraints.max_steps` &mdash; the CPU aborts after this many executed
  micro-operations.

Submit a program as JSON with the bytecode hex-encoded:

```json
{"type": "submit", "program": "060708090a"}
```

The server replies with either:

```json
{"type":"result","ok":true,"steps":42}
```

or

```json
{"type":"result","ok":false,"reason":"state_mismatch","got":{"regs":[...],"mem":"..."}}
```

After all rounds are won the service emits:

```json
{"type":"flag","flag":"TeamItaly{...}"}
```