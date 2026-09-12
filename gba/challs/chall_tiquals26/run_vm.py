#!/usr/bin/env python3

import argparse
import json
import os
import struct
import sys


IN_REGS_ADDR = 0x02000000
IN_MEM_ADDR = 0x02000040
IN_BC_LEN_ADDR = 0x02000140
IN_BC_ADDR = 0x02000144
OUT_REGS_ADDR = 0x02001000
OUT_MEM_ADDR = 0x02001040
OUT_STATUS_ADDR = 0x02001140
OUT_STEPS_ADDR = 0x02001144
OUT_DONE_ADDR = 0x02001148
ROM_DONE_MAGIC = 0xC0FFEE42

NREGS = 8
MEM_SIZE = 256


def _write_bytes(core, addr: int, data: bytes) -> None:
    mem = core.memory.u8
    for i, b in enumerate(data):
        mem[addr + i] = b


def _read_bytes(core, addr: int, length: int) -> bytes:
    mem = core.memory.u8
    return bytes(mem[addr + i] for i in range(length))


def _read_u32(core, addr: int) -> int:
    return struct.unpack("<I", _read_bytes(core, addr, 4))[0]


def run_rom(rom_path: str, regs: list[int], mem: bytes, bc: bytes, *, max_frames: int = 32) -> dict:
    if len(regs) != NREGS:
        raise ValueError(f"regs must contain {NREGS} entries")
    if len(mem) != MEM_SIZE:
        raise ValueError(f"mem must be {MEM_SIZE} bytes")

    import mgba.core
    import mgba.log
    mgba.log.silence()

    core = mgba.core.load_path(rom_path)
    if core is None:
        raise RuntimeError(f"failed to load ROM at {rom_path}")
    core.autoload_save()
    core.reset()

    _write_bytes(core, IN_REGS_ADDR, b"".join(struct.pack("<Q", r & ((1 << 64) - 1)) for r in regs))
    _write_bytes(core, IN_MEM_ADDR, mem)
    _write_bytes(core, IN_BC_LEN_ADDR, struct.pack("<I", len(bc)))
    _write_bytes(core, IN_BC_ADDR, bc)
    _write_bytes(core, OUT_DONE_ADDR, b"\x00\x00\x00\x00")

    completed = False
    for _ in range(max_frames):
        core.run_frame()

        out_regs = list(struct.unpack("<8Q", _read_bytes(core, IN_REGS_ADDR, 64)))
        print("regs")
        print(out_regs)

        if _read_u32(core, OUT_DONE_ADDR) == ROM_DONE_MAGIC:
            completed = True
            break

    if not completed:
        return {"status": -1, "regs": [0] * NREGS, "mem": "00" * MEM_SIZE, "steps": 0}

    out_regs = list(struct.unpack("<8Q", _read_bytes(core, OUT_REGS_ADDR, 64)))
    out_mem = _read_bytes(core, OUT_MEM_ADDR, MEM_SIZE)
    return {
        "status": _read_u32(core, OUT_STATUS_ADDR),
        "regs": out_regs,
        "mem": out_mem.hex(),
        "steps": _read_u32(core, OUT_STEPS_ADDR),
    }


def parse_job(text: str) -> tuple[list[int], bytes, bytes]:
    job = json.loads(text)
    regs = job.get("regs")
    if not isinstance(regs, list) or len(regs) != NREGS:
        raise ValueError("'regs' must be a list of 8 integers")
    regs = [int(r) & ((1 << 64) - 1) for r in regs]

    mem_hex = job.get("mem", "00" * MEM_SIZE)
    mem = bytes.fromhex(mem_hex)
    if len(mem) != MEM_SIZE:
        raise ValueError(f"'mem' must decode to {MEM_SIZE} bytes")

    prog_hex = job.get("program", "")
    if not isinstance(prog_hex, str):
        raise ValueError("'program' must be a hex string")
    bc = bytes.fromhex(prog_hex)
    return regs, mem, bc


def main() -> None:
    parser = argparse.ArgumentParser(description="Run vm.gba through mGBA.")
    parser.add_argument("--rom", default=os.environ.get("ROM_PATH", "vm.gba"),
                        help="path to vm.gba (default: ./vm.gba or $ROM_PATH)")
    parser.add_argument("--input", "-i", default=None,
                        help="read job JSON from this file instead of stdin")
    parser.add_argument("--max-frames", type=int, default=32,
                        help="frame budget before giving up (default 32)")
    args = parser.parse_args()

    text = open(args.input, "r").read() if args.input else sys.stdin.read()
    regs, mem, bc = parse_job(text)
    result = run_rom(args.rom, regs, mem, bc, max_frames=args.max_frames)
    json.dump(result, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
