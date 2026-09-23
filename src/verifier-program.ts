/**
 * Source of the root-owned farcmd verifier that is installed on each SSH target.
 *
 * It is written in Python 3 (standard library only) rather than POSIX sh because it runs as root
 * while reading paths that the target account controls. It therefore needs openat()-style
 * traversal with O_NOFOLLOW and fstat() on the opened descriptor, so that a symlink or hard link
 * planted by the target account can never make root read (and leak the hash of) another file.
 *
 * Placeholders are substituted by farcmd (@@ID@@, @@USER@@, @@SUDOERS@@) and, for the interpreter
 * path in the first line only, by the installer on the target (@@PYTHON@@). The installed file is
 * therefore byte-for-byte reproducible by farcmd once the interpreter path is known, which is how
 * the verifier's self-measurement is checked.
 *
 * Protocol (see docs/capability-integrity.md):
 *   stdin : "FARCMD-VERIFY 1 <64 lowercase hex nonce>\n"   (nothing else is accepted)
 *   stdout: canonical measurement lines ... "end\n" followed by "mac <hex HMAC-SHA256(secret, body)>\n"
 * No argument, environment variable or request field is ever used as a path or command.
 */
export const VERIFIER_PROGRAM_TEMPLATE = String.raw`#!@@PYTHON@@ -IS
# farcmd capability integrity verifier. Managed by farcmd; do not edit.
# Runs as root. Reads one challenge from stdin, measures the farcmd capability state of one
# account and returns the measurement authenticated with HMAC-SHA256 under a root-only secret.
import binascii, errno, hashlib, hmac, os, pwd, re, stat, subprocess, sys

VERIFIER_ID = "@@ID@@"
TARGET_USER = "@@USER@@"
SUDOERS_PATH = "@@SUDOERS@@"
SELF_PATH = "/usr/local/libexec/farcmd/verify-" + VERIFIER_ID
SECRET_PATH = "/etc/farcmd/verify-" + VERIFIER_ID + ".key"
CAP_DIR = (".ssh", "farcmd")
MAX_FILE = 4 * 1024 * 1024
MAX_ENTRIES = 4096
REQUEST = re.compile(rb"FARCMD-VERIFY 1 ([0-9a-f]{64})\n\Z")
SAFE = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-/~+")
RD = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_NOCTTY | getattr(os, "O_CLOEXEC", 0)
RDIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def die(reason, code=2):
    sys.stderr.write("farcmd-verify: " + reason + "\n")
    sys.exit(code)


def enc(value):
    if isinstance(value, str):
        value = os.fsencode(value)
    return "".join(chr(c) if c in SAFE else "%%%02X" % c for c in value) or "%00"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def mode(st):
    return "%04o" % stat.S_IMODE(st.st_mode)


def read_fd(fd, limit):
    chunks, total = [], 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        total += len(chunk)
        if total > limit:
            return None
        chunks.append(chunk)


def read_request():
    data = b""
    while len(data) < 128 and not data.endswith(b"\n"):
        chunk = os.read(0, 128 - len(data))
        if not chunk:
            break
        data += chunk
    match = REQUEST.match(data)
    if not match:
        die("malformed request")
    return match.group(1).decode("ascii")


def trust(path):
    """Every component of path (and of its resolved form) must be root-owned and not group/world writable."""
    for candidate in (path, os.path.realpath(path)):
        current = "/"
        components = [current]
        for part in candidate.strip("/").split("/"):
            current = os.path.join(current, part)
            components.append(current)
        for item in components:
            try:
                st = os.lstat(item)
            except OSError:
                return "bad:missing:" + enc(item)
            if st.st_uid != 0:
                return "bad:owner:" + enc(item)
            if not stat.S_ISLNK(st.st_mode) and st.st_mode & 0o022:
                return "bad:mode:" + enc(item)
    return "ok"


def open_root_file(path):
    fd = os.open(path, RD)
    st = os.fstat(fd)
    return fd, st


def measure_self():
    try:
        fd, st = open_root_file(SELF_PATH)
    except OSError:
        return "-", "bad:missing"
    try:
        data = read_fd(fd, MAX_FILE)
    finally:
        os.close(fd)
    state = trust(SELF_PATH)
    if state == "ok" and not stat.S_ISREG(st.st_mode):
        state = "bad:type"
    return (sha(data) if data is not None else "toolarge"), state


def load_secret():
    try:
        fd, st = open_root_file(SECRET_PATH)
    except OSError:
        die("verification secret unavailable", 3)
    try:
        raw = read_fd(fd, 256)
    finally:
        os.close(fd)
    state = trust(SECRET_PATH)
    if state == "ok" and (not stat.S_ISREG(st.st_mode) or st.st_mode & 0o077):
        state = "bad:mode"
    try:
        secret = bytes.fromhex((raw or b"").strip().decode("ascii"))
    except ValueError:
        die("verification secret malformed", 3)
    if len(secret) != 32:
        die("verification secret malformed", 3)
    return secret, state


def measure_sudoers():
    if not SUDOERS_PATH:
        return "absent", "-"
    try:
        fd, st = open_root_file(SUDOERS_PATH)
    except OSError:
        return "-", "bad:missing"
    try:
        data = read_fd(fd, 65536)
    finally:
        os.close(fd)
    state = trust(SUDOERS_PATH)
    if state == "ok" and not stat.S_ISREG(st.st_mode):
        state = "bad:type"
    return (sha(data) if data is not None else "toolarge"), state


def open_dir(name, parent_fd):
    try:
        return os.open(name, RDIR, dir_fd=parent_fd), "ok"
    except FileNotFoundError:
        return None, "absent"
    except NotADirectoryError:
        return None, "bad:notdir"
    except OSError as error:
        return None, "bad:symlink" if error.errno == errno.ELOOP else "bad:open"


def dir_line(label, fd, state):
    if fd is None:
        return "%s %s - -" % (label, state)
    st = os.fstat(fd)
    return "%s %s %d %s" % (label, state, st.st_uid, mode(st))


def measure_entries(cap_fd, uid, out):
    names = sorted(os.listdir(cap_fd), key=os.fsencode)
    if len(names) > MAX_ENTRIES:
        out.append("capdir-overflow %d" % len(names))
        names = names[:MAX_ENTRIES]
    for name in names:
        try:
            st = os.stat(name, dir_fd=cap_fd, follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISREG(st.st_mode):
            kind = "f"
        elif stat.S_ISDIR(st.st_mode):
            kind = "d"
        elif stat.S_ISLNK(st.st_mode):
            kind = "l"
        else:
            kind = "o"
        digest = "-"
        if kind == "f" and st.st_uid == uid:
            try:
                fd = os.open(name, RD, dir_fd=cap_fd)
            except OSError:
                digest = "changed"
            else:
                try:
                    fst = os.fstat(fd)
                    if stat.S_ISREG(fst.st_mode) and fst.st_uid == uid and (fst.st_dev, fst.st_ino) == (st.st_dev, st.st_ino):
                        data = read_fd(fd, MAX_FILE)
                        digest = sha(data) if data is not None else "toolarge"
                        st = fst
                    else:
                        digest = "changed"
                finally:
                    os.close(fd)
        out.append("cap %s %s %d %s %d %d %s" % (enc(name), kind, st.st_uid, mode(st), st.st_nlink, st.st_size, digest))


def sshd_settings():
    for candidate in ("/usr/sbin/sshd", "/usr/local/sbin/sshd", "/sbin/sshd"):
        if not os.path.isfile(candidate):
            continue
        spec = "user=%s,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22" % TARGET_USER
        try:
            result = subprocess.run([candidate, "-T", "-C", spec], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}, timeout=15)
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return None
        files, command = None, "none"
        for line in result.stdout.decode("utf-8", "replace").splitlines():
            key, _, value = line.partition(" ")
            if key == "authorizedkeysfile":
                files = value.split()
            elif key == "authorizedkeyscommand":
                command = value.strip() or "none"
        return (files or [".ssh/authorized_keys", ".ssh/authorized_keys2"]), command
    return None


def expand(token, account):
    out, index = "", 0
    while index < len(token):
        char = token[index]
        if char == "%":
            code = token[index + 1:index + 2]
            values = {"%": "%", "h": account.pw_dir, "u": account.pw_name, "U": str(account.pw_uid)}
            if code not in values:
                return None
            out += values[code]
            index += 2
            continue
        out += char
        index += 1
    return out


def open_beneath(base_fd, relative):
    parts = [part for part in relative.split("/") if part not in ("", ".")]
    if not parts or ".." in parts:
        raise OSError(22, "invalid path")
    fd = os.dup(base_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, RDIR, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        return os.open(parts[-1], RD, dir_fd=fd)
    finally:
        os.close(fd)


def key_blobs(line):
    found = set()
    for token in re.split(rb"[\s\",]+", line):
        if len(token) < 20 or not re.fullmatch(rb"[A-Za-z0-9+/]+=*", token):
            continue
        body = token.rstrip(b"=")
        body += b"=" * (-len(body) % 4)
        try:
            raw = binascii.a2b_base64(body)
        except (binascii.Error, ValueError):
            continue
        if len(raw) < 4:
            continue
        size = int.from_bytes(raw[:4], "big")
        if size < 3 or size > 64 or len(raw) < 4 + size or not re.fullmatch(rb"[a-z0-9@._-]+", raw[4:4 + size]):
            continue
        found.add(sha(raw))
    return sorted(found)


def measure_authorized_keys(home_fd, account, files, out):
    home_prefix = account.pw_dir.rstrip("/") + "/"
    for index, token in enumerate(files):
        if token == "none":
            continue
        path = expand(token, account)
        if path is None:
            out.append("akf %d %s bad:token -" % (index, enc(token)))
            continue
        try:
            if path.startswith(home_prefix):
                fd = open_beneath(home_fd, path[len(home_prefix):])
            elif not path.startswith("/"):
                fd = open_beneath(home_fd, path)
            else:
                parent = os.open(os.path.dirname(path), os.O_RDONLY | os.O_DIRECTORY)
                try:
                    fd = os.open(os.path.basename(path), RD, dir_fd=parent)
                finally:
                    os.close(parent)
        except FileNotFoundError:
            out.append("akf %d %s absent -" % (index, enc(path)))
            continue
        except OSError as error:
            out.append("akf %d %s %s -" % (index, enc(path), "bad:symlink" if error.errno == errno.ELOOP else "bad:open"))
            continue
        try:
            st = os.fstat(fd)
            data = read_fd(fd, MAX_FILE) if stat.S_ISREG(st.st_mode) else None
        finally:
            os.close(fd)
        if not stat.S_ISREG(st.st_mode):
            state = "bad:type"
        elif data is None:
            state = "bad:toolarge"
        elif st.st_uid not in (0, account.pw_uid):
            state = "bad:owner"
        elif st.st_mode & 0o022:
            state = "bad:mode"
        else:
            state = "ok"
        out.append("akf %d %s %s %s" % (index, enc(path), state, sha(data) if data is not None else "-"))
        if data is None:
            continue
        for number, line in enumerate(data.split(b"\n"), 1):
            stripped = line.lstrip(b" \t")
            if not stripped or stripped.startswith(b"#"):
                continue
            out.append("ak %d %d %s %s" % (index, number, sha(line), ",".join(key_blobs(line)) or "-"))


def main():
    nonce = read_request()
    if os.geteuid() != 0:
        die("verifier is not running as root", 3)
    secret, secret_state = load_secret()
    try:
        account = pwd.getpwnam(TARGET_USER)
    except KeyError:
        die("unknown target account", 3)
    out = ["farcmd-verify 1", "nonce " + nonce, "verifier " + VERIFIER_ID, "user %s %d" % (TARGET_USER, account.pw_uid)]
    out.append("python %s %s" % (enc(sys.executable), trust(sys.executable)))
    self_sha, self_state = measure_self()
    out.append("self %s %s" % (self_sha, self_state))
    out.append("secret " + secret_state)
    sudoers_sha, sudoers_state = measure_sudoers()
    out.append("sudoers %s %s" % (sudoers_sha, sudoers_state))
    try:
        home_fd = os.open(account.pw_dir, os.O_RDONLY | os.O_DIRECTORY)
        home_state = "ok"
    except OSError:
        home_fd, home_state = None, "bad:open"
    out.append(dir_line("home", home_fd, home_state))
    ssh_fd, state = open_dir(CAP_DIR[0], home_fd) if home_fd is not None else (None, "absent")
    cap_fd, cap_state = open_dir(CAP_DIR[1], ssh_fd) if ssh_fd is not None else (None, state)
    out.append(dir_line("capdir", cap_fd, cap_state))
    if cap_fd is not None:
        measure_entries(cap_fd, account.pw_uid, out)
    settings = sshd_settings()
    if settings is None:
        files, command, sshd_state = [".ssh/authorized_keys", ".ssh/authorized_keys2"], "none", "unavailable"
    else:
        (files, command), sshd_state = settings, "ok"
    out.append("sshd %s %s" % (sshd_state, enc(command)))
    if home_fd is not None:
        measure_authorized_keys(home_fd, account, files, out)
    out.append("end")
    body = ("\n".join(out) + "\n").encode("ascii")
    tag = hmac.new(secret, body, hashlib.sha256).hexdigest()
    sys.stdout.buffer.write(body + b"mac " + tag.encode("ascii") + b"\n")
    sys.stdout.buffer.flush()


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException:
        die("internal error", 70)
`;
