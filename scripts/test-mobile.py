#!/usr/bin/env python3
"""Smoke-test release UI using real PTYs, without root or firewall changes."""
import fcntl
import os
from pathlib import Path
import pty
import select
import struct
import subprocess
import tempfile
import termios
import time

binary = str(Path(__file__).resolve().parents[1] / "target/release/sentinela")
for width, height in [(20, 10), (32, 16), (40, 24), (69, 24), (80, 24), (120, 40)]:
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))
    original = termios.tcgetattr(slave)
    with tempfile.TemporaryDirectory(prefix="sentinela-pty-") as directory:
        environment = dict(os.environ, TERM="xterm-256color",
                           SSH_CONNECTION="192.0.2.1 54321 192.0.2.2 22")
        process = subprocess.Popen([binary, "--simulate", "0"], cwd=directory,
                                   stdin=slave, stdout=slave, stderr=slave,
                                   env=environment)
        output = bytearray()

        def drain(seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if select.select([master], [], [], 0.05)[0]:
                    output.extend(os.read(master, 65536))

        try:
            drain(2)
            assert process.poll() is None, bytes(output).decode(errors="replace")
            # Search, confirm, details, close, resize, then clean exit.
            os.write(master, b"/SSH\r")
            drain(0.3)
            os.write(master, b"\r")
            drain(0.3)
            os.write(master, b"\x1b")
            drain(0.3)
            fcntl.ioctl(slave, termios.TIOCSWINSZ,
                        struct.pack("HHHH", 20, 36, 0, 0))
            drain(0.3)
            os.write(master, b"q")
            drain(0.5)
            assert process.wait(timeout=5) == 0, bytes(output).decode(errors="replace")
            assert b"panicked" not in output
            assert termios.tcgetattr(slave) == original, "terminal settings not restored"
            assert b"\x1b[?1049l" in output, "alternate screen not restored"
            print(f"PASS {width}x{height}: search, details, resize, exit, terminal restored")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)
