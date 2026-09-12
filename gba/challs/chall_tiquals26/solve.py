#!/usr/bin/env python3
import heapq
import json
import socket
import time
from typing import Optional

try:
    import z3
except Exception:
    z3 = None

Z3_TIMEOUT_MS = 10000
WARNED_Z3 = False

MASK = (1 << 64) - 1

# Register indices
R0, R1, R2, R3, R4, R5, R6, R7 = range(8)

# Opcode read/write sets for dependency analysis
OP_READS = {
    0x00: {R0},
    0x01: {R0, R3},
    0x02: {R0},
    0x03: {R4},
    0x04: set(),
    0x05: {R6},
    0x06: {R4},
    0x07: {R5},
    0x08: {R0, R2},
    0x09: {R0, R3},
    0x0A: {R0, R4},
    0x0B: set(),
    0x0C: {R5},
    0x0D: {R0, R1},
    0x0E: {R2},
    0x0F: {R0, R1, R2},
    0x1B: {R4, R5},
    0x1C: {R5, R7},
}

OP_WRITES = {
    0x00: {R0, R1},
    0x01: {R3, R4},
    0x02: {R0, R5},
    0x03: {R0, R1},
    0x04: {R2},
    0x05: {R3, R6},
    0x06: {R0},
    0x07: {R0, R5},
    0x08: {R0, R2},
    0x09: {R0, R3},
    0x0A: {R4},
    0x0B: {R0},
    0x0C: {R0},
    0x0D: {R0, R1},
    0x0E: {R2},
    0x0F: {R0, R2},
    0x1B: {R4},
    0x1C: {R4, R5},
}


def step(op, regs):
    r0, r1, r2, r3, r4, r5, r6, r7 = regs
    if op == 0x00:
        r1, r0 = r0, 8
    elif op == 0x01:
        r4, r3 = r0, r3 ^ r0
    elif op == 0x02:
        r5, r0 = r0, (~1) & MASK
    elif op == 0x03:
        r1, r0 = 0, r4
    elif op == 0x04:
        r2 = 8
    elif op == 0x05:
        r3, r6 = 8, r6 ^ 8
    elif op == 0x06:
        r0 = r4
    elif op == 0x07:
        r0, r5 = r5, (~r5) & MASK
    elif op == 0x08:
        r2, r0 = r2 ^ r0, 16
    elif op == 0x09:
        r3, r0 = (r3 + r0) & MASK, r0 ^ ((r3 + r0) & MASK)
    elif op == 0x0A:
        r4 = (~(r4 + r0)) & MASK
    elif op == 0x0B:
        r0 = 1
    elif op == 0x0C:
        r0 = 1 ^ r5
    elif op == 0x0D:
        r1, r0 = (~r1) & MASK, (r0 + r0) & MASK
    elif op == 0x0E:
        r2 = (~r2) & MASK
    elif op == 0x0F:
        r0 = (r0 << (r1 & 63)) & MASK
        r2 ^= r0
    elif op == 0x1B:
        r4 = (r4 + (r5 * r4)) & MASK
    elif op == 0x1C:
        r4, r5 = r7, (r5 - r7) & MASK
    else:
        raise ValueError(f"Unknown opcode {op}")
    return (r0, r1, r2, r3, r4, r5, r6, r7)


def _compute_needed_regs(allowed_ops, focus_regs):
    needed = set(focus_regs)
    changed = True
    while changed:
        changed = False
        for op in allowed_ops:
            writes = OP_WRITES.get(op, set())
            if not (writes & needed):
                continue
            reads = OP_READS.get(op, set())
            for r in reads:
                if r not in needed:
                    needed.add(r)
                    changed = True
    return sorted(needed)


def _project_regs(full_regs, needed_regs):
    return tuple(full_regs[i] for i in needed_regs)


def _expand_regs(reduced_regs, needed_regs):
    full = [0] * 8
    for idx, reg_idx in enumerate(needed_regs):
        full[reg_idx] = reduced_regs[idx]
    return tuple(full)


def _symbolic_step(op, regs):
    r0, r1, r2, r3, r4, r5, r6, r7 = regs
    cases = [
        (0x00, (z3.BitVecVal(8, 64), r0, r2, r3, r4, r5, r6, r7)),
        (0x01, (r0, r1, r2, r3 ^ r0, r0, r5, r6, r7)),
        (0x02, (z3.BitVecVal(~1 & MASK, 64), r1, r2, r3, r4, r0, r6, r7)),
        (0x03, (r4, z3.BitVecVal(0, 64), r2, r3, r4, r5, r6, r7)),
        (0x04, (r0, r1, z3.BitVecVal(8, 64), r3, r4, r5, r6, r7)),
        (0x05, (r0, r1, r2, z3.BitVecVal(8, 64), r4, r5, r6 ^ 8, r7)),
        (0x06, (r4, r1, r2, r3, r4, r5, r6, r7)),
        (0x07, (r5, r1, r2, r3, r4, (~r5) & MASK, r6, r7)),
        (0x08, (z3.BitVecVal(16, 64), r1, r2 ^ r0, r3, r4, r5, r6, r7)),
        (0x09, (r0 ^ ((r3 + r0) & MASK), r1, r2, (r3 + r0) & MASK, r4, r5, r6, r7)),
        (0x0A, (r0, r1, r2, r3, (~(r4 + r0)) & MASK, r5, r6, r7)),
        (0x0B, (z3.BitVecVal(1, 64), r1, r2, r3, r4, r5, r6, r7)),
        (0x0C, (1 ^ r5, r1, r2, r3, r4, r5, r6, r7)),
        (0x0D, ((r0 + r0) & MASK, (~r1) & MASK, r2, r3, r4, r5, r6, r7)),
        (0x0E, (r0, r1, (~r2) & MASK, r3, r4, r5, r6, r7)),
        (0x0F, ((r0 << (r1 & 63)) & MASK, r1, r2 ^ ((r0 << (r1 & 63)) & MASK), r3, r4, r5, r6, r7)),
        (0x1B, (r0, r1, r2, r3, (r4 + r5 * r4) & MASK, r5, r6, r7)),
        (0x1C, (r0, r1, r2, r3, r7, (r5 - r7) & MASK, r6, r7)),
    ]

    def build_if(idx):
        if idx == len(cases) - 1:
            val, tup = cases[idx]
            return tuple(z3.If(op == val, tup[j], regs[j]) for j in range(8))
        val, tup = cases[idx]
        rest = build_if(idx + 1)
        return tuple(z3.If(op == val, tup[j], rest[j]) for j in range(8))

    return build_if(0)


def _solve_round_z3(init_regs, target_regs, allowed_ops, max_len, focus_regs, *, timeout_ms=Z3_TIMEOUT_MS) -> Optional[str]:
    if z3 is None:
        return None

    init = [z3.BitVecVal(r & MASK, 64) for r in init_regs]
    for length in range(1, max_len + 1):
        prog = [z3.BitVec(f"p{length}_{i}", 8) for i in range(length)]
        constraints = [z3.Or([p == op for op in allowed_ops]) for p in prog]

        regs = init
        for p in prog:
            regs = _symbolic_step(p, regs)

        for idx in focus_regs:
            if target_regs[idx] is not None:
                constraints.append(regs[idx] == target_regs[idx])

        solver = z3.Solver()
        solver.set("timeout", timeout_ms)
        solver.add(constraints)
        if solver.check() == z3.sat:
            model = solver.model()
            program = bytes([model[p].as_long() for p in prog])
            return program.hex()
    return None


def solve_round(
    init_regs,
    target_regs,
    allowed_ops,
    max_len,
    focus_regs,
    *,
    beam_size=20_000,
    max_candidates=80_000,
    max_seconds=2.0,
):
    # Fast feasibility check for r5 based on allowed ops
    if R5 in focus_regs and target_regs[R5] is not None:
        tgt_r5 = target_regs[R5]
        init_r5 = init_regs[R5] & MASK
        if 0x07 in allowed_ops:
            reachable_r5 = {init_r5, (~init_r5) & MASK}
        else:
            reachable_r5 = {init_r5}
        if tgt_r5 not in reachable_r5:
            return None

    global WARNED_Z3
    if z3 is None and not WARNED_Z3:
        print("[!] Z3 non disponibile: installa python-z3 per il fallback SMT.")
        WARNED_Z3 = True

    if z3 is not None:
        print(f"    Z3 timeout: {Z3_TIMEOUT_MS}ms")

    z3_answer = _solve_round_z3(
        init_regs,
        target_regs,
        allowed_ops,
        max_len,
        focus_regs,
    )
    if z3_answer is not None:
        return z3_answer
    needed_regs = _compute_needed_regs(allowed_ops, focus_regs)
    needed_set = set(needed_regs)
    reg_pos = {reg: idx for idx, reg in enumerate(needed_regs)}

    effective_ops = [
        op for op in allowed_ops if OP_WRITES.get(op, set()) & needed_set
    ]

    init_full = tuple(init_regs)
    init = _project_regs(init_full, needed_regs)

    # Precompute focus checks
    focus_checks = []
    for reg_idx in focus_regs:
        tgt = target_regs[reg_idx]
        if tgt is not None:
            focus_checks.append((reg_pos[reg_idx], tgt))

    def focus_ok(state):
        for pos, tgt in focus_checks:
            if state[pos] != tgt:
                return False
        return True

    if focus_ok(init):
        return ""

    beam = [(0, init, b"")]
    visited = {init}
    deadline = time.monotonic() + max_seconds

    for depth in range(1, max_len + 1):
        if not beam:
            break
        if time.monotonic() > deadline:
            return None
        next_candidates = {}
        expanded = 0
        last_tick = time.monotonic()
        for _score, state, prog in beam:
            full_state = _expand_regs(state, needed_regs)
            for op in effective_ops:
                if time.monotonic() > deadline:
                    return None
                new_full = step(op, full_state)
                new_state = _project_regs(new_full, needed_regs)
                if new_state in visited:
                    continue
                new_prog = prog + bytes([op])
                if focus_ok(new_state):
                    return new_prog.hex()
                visited.add(new_state)
                expanded += 1
                if expanded > max_candidates:
                    break
                if new_state not in next_candidates:
                    next_candidates[new_state] = new_prog
            if expanded > max_candidates:
                break
            now = time.monotonic()
            if now - last_tick > 0.25:
                print(f"    depth {depth}: expanded={expanded} candidates={len(next_candidates)}")
                last_tick = now

        if not next_candidates:
            break

        scored = []
        for state, prog in next_candidates.items():
            score = 0
            for pos, tgt in focus_checks:
                if state[pos] != tgt:
                    score += 1
            scored.append((score, state, prog))

        beam = heapq.nsmallest(beam_size, scored, key=lambda x: x[0])
        if depth < max_len:
            print(f"    depth {depth}: beam={len(beam)} candidates={len(scored)}")

    return None


def main():
    HOST = "10.100.0.2"
    PORT = 38087
    try:
        sock = socket.create_connection((HOST, PORT), timeout=10)
    except Exception as e:
        print(f"Connessione fallita: {e}")
        return
    f = sock.makefile("rw")
    warned_mem = False
    while True:
        line = f.readline()
        if not line:
            break
        data = json.loads(line)
        if data["type"] == "flag":
            print(f"\n[FLAG] {data['flag']}")
            break
        if data["type"] == "round":
            idx = data["index"]
            print(f"\n[*] Round {idx}")
            init_regs = data["input"]["regs"]
            tgt_regs = data["target"]["regs"]
            allowed = data["constraints"]["allowed_opcodes"]
            max_len = data["constraints"]["max_program_bytes"]
            focus = data["target"]["focus"]["regs"]
            mem_ranges = data["target"]["focus"].get("mem_ranges", [])
            if mem_ranges and not warned_mem:
                print("[!] Attenzione: i vincoli su mem_ranges non sono gestiti.")
                warned_mem = True
            print(f"    allowed ops: {allowed}")
            print(f"    max length: {max_len}")
            print(f"    focus registers: {focus}")
            print(f"    target regs (focused): {[(i, tgt_regs[i]) for i in focus]}")
            prog_hex = solve_round(init_regs, tgt_regs, allowed, max_len, focus)
            if prog_hex is None:
                print("[!] No solution found, aborting")
                break
            print(f"[+] Found program: {prog_hex}")
            submit = json.dumps({"type": "submit", "program": prog_hex})
            f.write(submit + "\n")
            f.flush()
            result = json.loads(f.readline())
            print(f"    server reply: {result}")
    sock.close()


if __name__ == "__main__":
    main()
