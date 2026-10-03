"""POSIX real-TTY CLI integration test; all secrets are public test strings."""
import os
import pty
import select
import signal
import tempfile
import termios
import time
from pathlib import Path

EXE = str(Path(__file__).resolve().parents[1] / "target/release/withcrypt")
PASSWORD = "공개 CLI 테스트 123".encode()

def run(args, passwords, expected=0):
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(EXE, [EXE, *map(str, args)])
    deadline = time.monotonic() + 30
    output = b""
    sent = 0
    prompts = ["비밀번호: ".encode(), "비밀번호 확인: ".encode()]
    try:
        while True:
            if time.monotonic() > deadline:
                os.kill(pid, signal.SIGKILL)
                raise AssertionError(("CLI timeout",sent,output.decode(errors="replace")))
            if select.select([fd], [], [], 0.1)[0]:
                try:
                    data = os.read(fd, 4096)
                except OSError:
                    break
                if not data:
                    break
                output += data
                if sent < len(passwords) and prompts[sent] in output:
                    os.write(fd, passwords[sent]+b"\n")
                    sent += 1
        _, status = os.waitpid(pid, 0)
        code = os.waitstatus_to_exitcode(status)
        assert code == expected, (code, output.decode(errors="replace"))
        assert PASSWORD not in output, "password echoed"
        assert termios.tcgetattr(fd)[3] & termios.ECHO, "terminal echo not restored"
    finally:
        os.close(fd)

with tempfile.TemporaryDirectory(prefix="withcrypt-cli-") as directory:
    root = Path(directory)
    source = root / "한글 파일.bin"
    data = bytes(range(256))*4097
    source.write_bytes(data)
    for suite in ["xchacha20-poly1305", "aes-256-gcm"]:
        encrypted = root / (suite+".esb")
        restored = root / (suite+".bin")
        run(["encrypt", source, "--output", encrypted, "--algorithm", suite], [PASSWORD, PASSWORD])
        run(["verify", encrypted], [PASSWORD])
        run(["decrypt", encrypted, "--output", restored], [b"wrong"], 3)
        assert not restored.exists()
        run(["decrypt", encrypted, "--output", restored], [PASSWORD])
        assert restored.read_bytes() == source.read_bytes() == data
        run(["decrypt", encrypted, "--output", restored], [PASSWORD], 4)
        assert restored.read_bytes() == data
        run(["verify", encrypted], [b"\x03"], 130)
        print(f"{suite}: real TTY encrypt/verify/decrypt, no echo, bad password, no-clobber passed")
