"""Line-delimited JSON provisioning protocol over the ESP32-S3 USB Serial/JTAG port."""

from __future__ import annotations

import json
import time
from typing import Any

import serial


class DeviceError(RuntimeError):
    pass


class Device:
    """Talks to a device in provision mode.

    Requests:  {"id": N, "cmd": "...", ...}\\n
    Responses: @@{"id": N, "ok": true, "result": {...}}\\n   (other lines are logs)
    """

    def __init__(self, port: str, timeout: float = 15.0, verbose: bool = False):
        self.verbose = verbose
        self.timeout = timeout
        self._id = 0
        s = serial.Serial()
        s.port = port
        s.baudrate = 115200
        s.timeout = 0.5
        # The ESP32-S3 USB Serial/JTAG resets the chip whenever RTS=1 and DTR=0.
        # The OS opens the tty with both asserted and pyserial then applies DTR
        # before RTS, so requesting dtr=False would pass through (RTS=1, DTR=0)
        # and reset the chip out of provision mode. Keep DTR asserted while RTS
        # is released (DTR=1, RTS=0 is harmless while running), then drop DTR.
        s.dtr = True
        s.rts = False
        s.open()
        s.dtr = False
        self.ser = s

    def close(self) -> None:
        self.ser.close()

    def __enter__(self) -> "Device":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def call(self, cmd: str, **params: Any) -> dict:
        self._id += 1
        req = {"id": self._id, "cmd": cmd, **params}
        self.ser.reset_input_buffer()
        self.ser.write((json.dumps(req, separators=(",", ":")) + "\n").encode())
        self.ser.flush()
        deadline = time.monotonic() + self.timeout
        buf = b""
        while time.monotonic() < deadline:
            chunk = self.ser.readline()
            if not chunk:
                continue
            buf += chunk
            if not buf.endswith(b"\n"):
                continue
            line, buf = buf.decode(errors="replace").strip(), b""
            if not line.startswith("@@"):
                if self.verbose and line:
                    print(f"[device] {line}")
                continue
            resp = json.loads(line[2:])
            if resp.get("id") not in (self._id, None):
                continue
            if not resp.get("ok"):
                raise DeviceError(f"{cmd}: {resp.get('error')}")
            return resp.get("result") or {}
        raise DeviceError(
            f"{cmd}: no response within {self.timeout}s. Is the device in provision mode "
            "(solid blue LED)? Press BOOT within 3 s after reset, or hold it for 5 s while running."
        )
