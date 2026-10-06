"""Just enough shell parsing to tell *where* a command points, not only *what* it says.

Week 1 measured two families of false positive in Claude Code hook traffic that a
regex over the whole command line can't avoid:

  * `rm -rf "$OUT/x"` where OUT is a folder in the system temp directory (Claude's
    own scratchpad) scored like `rm -rf ~`.
  * `docker compose --env-file .env.x build` and `git check-ignore .env` were
    treated as *reading* the credential file, though its contents never reach
    the agent.

This module splits a command into simple commands (quote-aware, heredoc bodies
skipped), follows plain variable assignments and `cd`, and answers two narrow
questions: is every target of a delete inside a temp directory, and is a given
credential path only *mentioned* rather than read. It is deliberately
conservative: anything it can't resolve - an unknown variable, a command
substitution, `..` - counts as "not provably safe", so the caller keeps flagging.

Bash, PowerShell and cmd syntax are handled to the extent seen in real agent
traffic; this is not a shell interpreter.
"""

from __future__ import annotations

import posixpath
import re
import tempfile
from dataclasses import dataclass, field

# --- splitting ----------------------------------------------------------------
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][\w]*)\1")
_SEPARATORS = ("&&", "||", ";", "|", "&", "\n")
#: Leading words that don't name the command itself.
_PREFIX_WORDS = frozenset({
    "do", "then", "else", "elif", "{", "(", "!", "time", "sudo", "nohup", "env",
    "command", "exec", "builtin", "noglob", "try", "finally",
})


@dataclass
class SimpleCommand:
    start: int                    # span in the original command line
    end: int
    words: list[str]              # quote-stripped words, prefixes removed
    verb: str = ""                # first word, lower-cased, basename, no .exe
    redirect_targets: list[str] = field(default_factory=list)

    @property
    def args(self) -> list[str]:
        return self.words[1:]


def _heredoc_bodies(command: str) -> list[tuple[int, int]]:
    """Character spans of heredoc bodies (the text between `<<EOF` and `EOF`)."""
    spans: list[tuple[int, int]] = []
    for m in _HEREDOC.finditer(command):
        body_start = command.find("\n", m.end())
        if body_start < 0:
            continue
        body_start += 1
        end_rx = re.compile(r"^[ \t]*" + re.escape(m.group(2)) + r"[ \t]*$", re.MULTILINE)
        close = end_rx.search(command, body_start)
        body_end = close.start() if close else len(command)
        spans.append((body_start, body_end))
    return spans


def _segments(command: str) -> list[tuple[int, int]]:
    """Spans of simple commands: split on unquoted separators, heredocs skipped."""
    bodies = _heredoc_bodies(command)
    spans: list[tuple[int, int]] = []
    start = i = 0
    quote = ""
    n = len(command)
    while i < n:
        inside = next((b for b in bodies if b[0] <= i < b[1]), None)
        if inside is not None:
            if start < inside[0]:
                spans.append((start, inside[0]))
            i = start = inside[1]
            # skip the closing delimiter line
            nl = command.find("\n", i)
            i = start = n if nl < 0 else nl + 1
            continue
        ch = command[i]
        if quote:
            if ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                i += 1
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            i += 1
            continue
        sep = next((s for s in _SEPARATORS if command.startswith(s, i)), None)
        if sep is not None and not (sep in ("&", "|") and command[i - 1:i] in (">", "<")):
            if start < i:
                spans.append((start, i))
            i += len(sep)
            start = i
            continue
        i += 1
    if start < n:
        spans.append((start, n))
    return [(a, b) for a, b in spans if command[a:b].strip()]


_WORD = re.compile(r"""(?:"[^"]*"|'[^']*'|[^\s"'])+""")


def _words(text: str) -> list[str]:
    return [w.replace('"', "").replace("'", "") for w in _WORD.findall(text)]


def _verb(word: str) -> str:
    base = word.replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base[:-4] if base.endswith(".exe") else base


def simple_commands(command: str) -> list[SimpleCommand]:
    out: list[SimpleCommand] = []
    for a, b in _segments(command):
        words = _words(command[a:b])
        targets: list[str] = []
        kept: list[str] = []
        redirect_next = False
        for w in words:
            if redirect_next:
                targets.append(w)
                redirect_next = False
                continue
            m = re.match(r"^\d?(>>?|<)(.*)$", w)
            if m and not w.startswith("<<"):
                if m.group(1).startswith(">"):
                    if m.group(2) and not m.group(2).startswith("&"):
                        targets.append(m.group(2))
                    elif not m.group(2):
                        redirect_next = True
                    continue
                kept.append(m.group(2)) if m.group(2) else None   # `< file`: an input
                continue
            kept.append(w)
        while kept:
            if kept[0].lower() in _PREFIX_WORDS:
                kept = kept[1:]
            elif _ASSIGN.match(kept[0]) and any(not _ASSIGN.match(k) for k in kept[1:]):
                kept = kept[1:]                     # `VAR=x cmd`: per-command assignment
            else:
                break
        out.append(SimpleCommand(a, b, kept, _verb(kept[0]) if kept else "", targets))
    return out


# --- variables and paths ----------------------------------------------------------
_ASSIGN = re.compile(r"^(?:export\s+)?([A-Za-z_]\w*)=(.*)$", re.DOTALL)
_PS_ASSIGN = re.compile(r"^\$([A-Za-z_]\w*)$")
_VAR = re.compile(r"\$\{([A-Za-z_]\w*)\}|\$env:([A-Za-z_]\w*)|\$([A-Za-z_]\w*)|%([A-Za-z_]\w*)%",
                  re.IGNORECASE)
TEMP = "<temp>"
HOME = "<home>"
_TEMP_VARS = frozenset({"tmpdir", "temp", "tmp", "runner_temp"})
_HOME_VARS = frozenset({"home", "userprofile"})


def _norm(path: str) -> str:
    """Comparable form: forward slashes, lower case, `/c/x` -> `c:/x`."""
    p = path.replace("\\", "/").strip()
    m = re.match(r"^/([a-zA-Z])(/|$)", p)
    if m and not p.startswith(("/tmp", "/var", "/private")):
        p = f"{m.group(1)}:/{p[3:]}"
    p = re.sub(r"/{2,}", "/", p).lower()
    return p


def _temp_roots() -> list[str]:
    roots = ["/tmp", "/var/tmp", "/private/tmp", TEMP]
    try:
        roots.append(_norm(tempfile.gettempdir()))
    except Exception:                                        # noqa: BLE001
        pass
    return roots


_TEMP_PATTERNS = (
    re.compile(r"^[a-z]:/users/[^/]+/appdata/local/temp(/|$)"),
    re.compile(r"^[a-z]:/windows/temp(/|$)"),
    re.compile(r"^(/private)?/var/folders/[^/]+/[^/]+/t(/|$)"),
)


def strictly_inside_temp(path: str) -> bool:
    """True if `path` (normalised) lies *below* a temp directory, not at its root."""
    p = _norm(path).rstrip("/")
    if not p or ".." in p.split("/"):
        return False
    for rx in _TEMP_PATTERNS:
        m = rx.match(p + "/")
        if m and len(p) > len(m.group(0).rstrip("/")):
            return True
    for root in _temp_roots():
        root = root.rstrip("/")
        if root and p.startswith(root + "/") and len(p) > len(root) + 1:
            return True
    return False


@dataclass
class _Expanded:
    fixed: str          # text up to the first part that can't be resolved
    complete: bool      # the whole word resolved, with no glob characters


def _expand(word: str, env: dict[str, str]) -> _Expanded:
    if "$(" in word or "`" in word:
        return _Expanded(word[:word.find("$(") if "$(" in word else word.find("`")], False)
    if word == "~" or word.startswith(("~/", "~\\")):
        word = HOME + word[1:]
    out = ""
    pos = 0
    for m in _VAR.finditer(word):
        out += word[pos:m.start()]
        name = next(g for g in m.groups() if g)
        low = name.lower()
        if name in env:
            out += env[name]
        elif low in _TEMP_VARS:
            out += TEMP
        elif low in _HOME_VARS:
            out += HOME
        else:
            return _Expanded(out, False)
        pos = m.end()
    out += word[pos:]
    glob_at = min((out.find(c) for c in "*?[" if c in out), default=-1)
    if glob_at >= 0:
        return _Expanded(out[:glob_at], False)
    return _Expanded(out, True)


def _is_abs(path: str) -> bool:
    p = path.replace("\\", "/")
    return p.startswith(("/", TEMP, HOME)) or bool(re.match(r"^[a-zA-Z]:/", p))


def _join(cwd: str | None, path: str) -> str | None:
    if _is_abs(path):
        return path
    if cwd is None:
        return None
    return posixpath.join(cwd.replace("\\", "/"), path.replace("\\", "/"))


def _target_in_temp(word: str, env: dict[str, str], cwd: str | None) -> bool:
    exp = _expand(word, env)
    fixed = exp.fixed
    if HOME in fixed:
        return False
    if not exp.complete:
        # Something after `fixed` is unknown. Safe only if, whatever it is, the
        # result stays below a temp directory: `fixed` must end inside one.
        if not fixed or fixed.endswith(("/", "\\")):
            fixed = fixed.rstrip("/\\")
            if not fixed:
                return False
    full = _join(cwd, fixed)
    return full is not None and strictly_inside_temp(full)


# --- deletes ------------------------------------------------------------------
_DELETE_VERBS = frozenset({"rm", "remove-item", "ri", "rmdir", "rd", "del", "erase"})
#: PowerShell parameters whose next word is a value, not a target.
_PS_VALUE_PARAMS = frozenset({
    "-erroraction", "-ea", "-include", "-exclude", "-filter", "-warningaction",
    "-wa", "-stream", "-credential", "-informationaction", "-ia",
})
_PS_PATH_PARAMS = frozenset({"-path", "-literalpath", "-lp", "-pspath"})


def _delete_targets(cmd: SimpleCommand) -> list[str]:
    targets: list[str] = []
    args = cmd.args
    i = 0
    end_of_options = False
    while i < len(args):
        a = args[i]
        low = a.lower()
        if not end_of_options and a == "--":
            end_of_options = True
        elif not end_of_options and low in _PS_PATH_PARAMS and i + 1 < len(args):
            targets.extend(p for p in args[i + 1].split(",") if p)
            i += 1
        elif not end_of_options and low in _PS_VALUE_PARAMS:
            i += 1
        elif not end_of_options and (a.startswith("-") or re.fullmatch(r"/[A-Za-z]", a)):
            pass                                            # a switch
        else:
            targets.extend(p for p in a.split(",") if p)
        i += 1
    return targets


@dataclass
class DeleteCheck:
    start: int
    end: int
    targets: list[str]
    in_temp: bool


def delete_checks(command: str) -> list[DeleteCheck]:
    """Every delete command in `command`, and whether all its targets are in temp.

    A relative target counts only after a `cd` into temp in the same command. The
    session's working directory never does: a project that happens to live under
    /tmp is still a project, and deleting inside it keeps going to REVIEW.
    """
    env: dict[str, str] = {}
    here: str | None = None
    checks: list[DeleteCheck] = []
    for cmd in simple_commands(command):
        words = cmd.words[1:] if cmd.words[:1] == ["export"] else cmd.words
        if not words:
            continue
        # plain assignments: OUT="..." (bash) or $OUT = "..." (PowerShell)
        if all(_ASSIGN.match(w) for w in words):
            for w in words:
                name, value = _ASSIGN.match(w).groups()                    # type: ignore[union-attr]
                exp = _expand(value, env)
                if exp.complete:
                    env[name] = exp.fixed
                else:
                    env.pop(name, None)
            continue
        ps_one = re.match(r"^\$([A-Za-z_]\w*)=(.+)$", words[0]) if len(words) == 1 else None
        if ps_one and not ps_one.group(1).lower() == "env":
            exp = _expand(ps_one.group(2), env)              # $p="C:\...\Temp\x"
            if exp.complete:
                env[ps_one.group(1)] = exp.fixed
            else:
                env.pop(ps_one.group(1), None)
            continue
        if len(words) >= 3 and _PS_ASSIGN.match(words[0]) and words[1] == "=":
            name = _PS_ASSIGN.match(words[0]).group(1)                     # type: ignore[union-attr]
            exp = _expand(" ".join(words[2:]), env)
            if exp.complete and len(words) == 3:
                env[name] = exp.fixed
            else:
                env.pop(name, None)
            continue
        if cmd.verb in ("cd", "pushd", "set-location", "sl", "chdir"):
            dest = next((a for a in cmd.args if not a.startswith("-")), None)
            exp = _expand(dest, env) if dest else None
            if exp is None or not exp.complete or HOME in exp.fixed:
                here = None
            else:
                here = _join(here, exp.fixed)
            continue
        if cmd.verb in _DELETE_VERBS:
            targets = _delete_targets(cmd)
            ok = bool(targets) and all(_target_in_temp(t, env, here) for t in targets)
            checks.append(DeleteCheck(cmd.start, cmd.end, targets, ok))
    return checks


def only_temp_deletes(command: str, match_starts: list[int]) -> bool:
    """True if every destructive-pattern match lies in a delete whose targets are
    all inside a temp directory."""
    if not match_starts:
        return False
    checks = delete_checks(command)
    for pos in match_starts:
        owner = next((c for c in checks if c.start <= pos < c.end), None)
        if owner is None or not owner.in_temp:
            return False
    return True


# --- credential paths: read, or only mentioned? ---------------------------------
#: Commands that use a path without printing the file's contents.
_REFERENCE_VERBS = frozenset({
    "ls", "dir", "stat", "test", "[", "[[", "touch", "chmod", "chown", "attrib", "icacls",
    "rm", "del", "erase", "mkdir", "which", "where", "echo", "printf", "find", "fd",
    "du", "wc", "source", ".", "test-path", "get-item", "gi", "get-childitem", "gci",
    "remove-item", "ri", "new-item", "ni",
})
_GIT_REFERENCE = frozenset({"status", "add", "rm", "mv", "check-ignore", "ls-files", "restore",
                            "checkout", "update-index", "clean", "stash"})
_CONTAINER = frozenset({"docker", "docker-compose", "podman", "podman-compose"})


def _mentions(word: str, token: str) -> bool:
    return word == token or word.endswith("=" + token) or word.endswith(":" + token)


def only_mentioned(command: str, token: str) -> bool:
    """True if every occurrence of the path `token` is in a command that doesn't
    print its contents (ls, test, git check-ignore, docker --env-file, a redirect
    target...). Occurrences the parser can't attribute count as reads."""
    seen = 0
    for cmd in simple_commands(command):
        for target in cmd.redirect_targets:
            if _mentions(target, token):
                seen += 1                                   # written to, not read
        for i, word in enumerate(cmd.words):
            if not _mentions(word, token):
                continue
            if i == 0:
                return False
            verb = cmd.verb
            prev = cmd.words[i - 1].lower()
            loads = (prev == "--env-file" or word.lower().startswith("--env-file=")
                     or ("dotenv" in cmd.words and prev in ("-f", "--file")))
            if loads and verb not in _CONTAINER and verb != "compose":
                pass        # uvicorn --env-file, python -m dotenv -f X run: loaded, not shown
            elif verb == "git":
                sub = next((w for w in cmd.args if not w.startswith("-")), "")
                if sub not in _GIT_REFERENCE:
                    return False
            elif verb in _CONTAINER or (verb == "compose"):
                flag = cmd.words[i - 1].lower()
                inline = word.lower().startswith("--env-file=")
                if not (flag == "--env-file" or inline) or "config" in [w.lower() for w in cmd.args]:
                    return False
            elif verb not in _REFERENCE_VERBS:
                return False
            seen += 1
    whole = re.compile(r"(?<![\w./\\-])" + re.escape(token) + r"(?![\w./\\-])")
    return seen > 0 and seen >= len(whole.findall(command))
