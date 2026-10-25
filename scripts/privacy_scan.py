#!/usr/bin/env python3
"""Fail-closed, dependency-free privacy checks. Never return matched values."""
import argparse
import base64
import bz2
import gzip
import lzma
import hashlib
import io
import posixpath
import json
import re
import subprocess
import sys
import tarfile
import urllib.parse
import zipfile
from pathlib import Path, PurePosixPath

MAX_FILE = 256 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 100000
RULES = {
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----[\s\S]{1,30000}?-----END (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "access_token": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{25,}|github_pat_[A-Za-z0-9_]{25,})\b"),
    "password_hash": re.compile(rb"\$argon2(?:id|i|d)\$v=\d+\$[A-Za-z0-9$,=/+]{20,}"),
    "credential_assignment": re.compile(rb"""(?im)(?:^|[\s{,;])["']?(?:username|display_name|student_id|password|current_password|new_password|password_hash|token_hash|csrf|passwd|browser_fingerprint|MULTIFACTOR_BROWSER_FINGERPRINT|cookie|authorization|secret_key|api_key|access_token|refresh_token)["']?\s*[:=]\s*["']([^"'\r\n]{1,1024})["']"""),
    "credential_environment": re.compile(rb"(?im)^(?:[A-Z_]*(?:PASSWORD|PASSWD|TOKEN|SECRET|COOKIE|FINGERPRINT|PRIVATE_KEY|API_KEY)|JSESSIONID|CASTGC)=([^\r\n]{1,4096})"),
    "cookie_header": re.compile(rb"(?im)^\s*(?:Cookie|Set-Cookie|Authorization)\s*:\s*([^\r\n]{5,4096})"),
    "user_data_export": re.compile(rb"(?im)^\s*INSERT\s+INTO\s+[\x60\"[]?(?:web_users|web_accounts|web_sessions|web_cookies)\b"),
    "machine_path": re.compile(rb"""[A-Za-z]:[\\/](?:Users|MoonUESTC)[\\/][^\r\n"\x27<>]{1,512}"""),
}
UNWAIVABLE = {"private_marker", "private_runtime_path", "database_content",
              "cookie_store", "encrypted_runtime_content", "unsafe_archive",
              "scan_error", "invalid_image", "scan_limit", "user_data_table", "unsupported_archive"}
PLACEHOLDER = re.compile(rb"^(?:PUT_[A-Z0-9_]+|YOUR_[A-Z0-9_]+|<[^>]+>|\$\{[^}]+\})$")
PRIVATE_DIRS = {"data", "config", "backups", "release-artifacts", ".ssh", ".aws", ".codex"}
PRIVATE_NAMES = {"dashboard.key", "state.sqlite3", "dashboard.sqlite3", "private-markers.json",
                 "baseline-private.json", "release-state.json", "AGENTS.md"}
SUFFIXES = (".sqlite3", ".sqlite3-wal", ".sqlite3-shm", ".db", ".lwp", ".p12", ".pfx")

def run_git(root, *args, data=None):
    r = subprocess.run(["git", "-C", str(root), *args], input=data, capture_output=True)
    if r.returncode:
        raise ValueError("git_read_failed")
    return r.stdout

def safe_name(name):
    parts = PurePosixPath(name.replace("\\", "/")).parts
    if not parts or name.startswith(("/", "\\")) or ".." in parts or re.match(r"^[A-Za-z]:", name):
        raise ValueError("unsafe_archive")
    return "/".join(p for p in parts if p != ".")

def path_rule(name, image=False):
    name = safe_name(name)
    p = PurePosixPath(name)
    parts = p.parts
    base = p.name.lower()
    if image:
        if any(name.startswith(x) for x in ("data/", "config/", "app/data/", "app/config/",
                                             "root/.ssh/", "root/.aws/", "etc/letsencrypt/")):
            return True
        if base.endswith(SUFFIXES) or base == ".env":
            return True
        if name.startswith("app/"):
            return path_rule(name[4:])
        return False
    return (any(x.lower() in PRIVATE_DIRS for x in parts) or p.name in PRIVATE_NAMES
            or base == ".env" or (base.startswith(".env.") and base != ".env.example")
            or base.endswith(SUFFIXES + (".pem", ".key"))
            or base.startswith("shanghai-"))

class Scanner:
    def __init__(self, allowlist=None, markers=()):
        self.allow = set()
        if allowlist:
            value = json.loads(Path(allowlist).read_text(encoding="utf-8"))
            if value.get("version") != 1:
                raise ValueError("invalid_allowlist")
            for x in value["exceptions"]:
                if not x.get("reason") or x["rule"] in UNWAIVABLE:
                    raise ValueError("invalid_allowlist")
                self.allow.add((x["rule"], x["path"], x["match_sha256"]))
        self.markers = set()
        for raw in markers:
            if not raw:
                continue
            raw = raw.encode() if isinstance(raw, str) else bytes(raw)
            self.markers.add(raw)
            self.markers.add(base64.b64encode(raw))
            self.markers.add(raw.hex().encode())
            try:
                text = raw.decode()
            except UnicodeError:
                continue
            self.markers.add(urllib.parse.quote(text, safe="").encode())
            self.markers.add(json.dumps(text, ensure_ascii=True)[1:-1].encode())
        self.findings = []
        self.waived = []
        self.files = 0
        self.total = 0
        self.layers = 0
        self._seen = set()

    def finding(self, rule, path, match=b""):
        digest = hashlib.sha256(match).hexdigest()
        key = (rule, path, digest)
        if key in self._seen:
            return
        self._seen.add(key)
        item = {"rule": rule, "path": path, "match_sha256": digest}
        if rule not in UNWAIVABLE and key in self.allow:
            self.waived.append(item)
        else:
            self.findings.append(item)

    def name_check(self,path):
        if any(x in path.encode("utf-8") for x in self.markers):
            self.finding("private_marker",path)

    def data(self, path, raw, image=False):
        self.name_check(path)
        self.files += 1
        self.total += len(raw)
        if self.files > MAX_MEMBERS or len(raw) > MAX_FILE or self.total > MAX_TOTAL:
            raise ValueError("scan_limit")
        if path_rule(path, image):
            self.finding("private_runtime_path", path)
        if raw.startswith((b"7z\xbc\xaf\x27\x1c", b"Rar!\x1a\x07", b"\x28\xb5\x2f\xfd")):
            raise ValueError("unsupported_archive")
        if re.search(rb"(?im)^(?:username|student_id|user_id),[^\r\n]*(?:password|cookie|fingerprint|display_name)[^\r\n]*\r?\n[^\r\n]+", raw):
            self.finding("user_data_table", path)
        if raw.startswith(b"SQLite format 3\x00"):
            self.finding("database_content", path)
        if raw.startswith(b"MW1") and len(raw) >= 31:
            self.finding("encrypted_runtime_content", path)
        if b"LWP-Cookies-" in raw[:200] or b"Netscape HTTP Cookie File" in raw[:200]:
            self.finding("cookie_store", path)
        if any(x in raw for x in self.markers):
            self.finding("private_marker", path)
        complete_keys=list(RULES["private_key"].finditer(raw))
        for header in re.finditer(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",raw):
            if not any(m.start()<=header.start()<m.end() for m in complete_keys):
                self.finding("private_key_fragment",path,raw)
        for rule, pattern in RULES.items():
            for match in pattern.finditer(raw):
                captured = match.group(1) if match.lastindex else match.group()
                if rule in ("credential_assignment","credential_environment") and PLACEHOLDER.fullmatch(captured):
                    continue
                self.finding(rule, path, match.group())

    def _read(self, stream, size=None):
        if size is not None and size > MAX_FILE:
            raise ValueError("scan_limit")
        raw = stream.read(MAX_FILE + 1)
        if len(raw) > MAX_FILE:
            raise ValueError("scan_limit")
        return raw

    def archive(self, raw, label, depth=0, image=False):
        if depth > 5:
            raise ValueError("scan_limit")
        stream = io.BytesIO(raw)
        if zipfile.is_zipfile(stream):
            stream.seek(0)
            with zipfile.ZipFile(stream) as z:
                for item in z.infolist():
                    name = safe_name(item.filename)
                    if item.is_dir():
                        continue
                    if item.flag_bits & 1 or ((item.external_attr >> 16) & 0o170000) == 0o120000:
                        raise ValueError("unsafe_archive")
                    data = self._read(z.open(item), item.file_size)
                    self.entry(label+"!/"+name if image else name, data, depth+1, image)
        else:
            stream.seek(0)
            with tarfile.open(fileobj=stream, mode="r:*") as t:
                names = {m.name for m in t.getmembers()}
                if "manifest.json" in names:
                    self.docker_archive(t, label)
                    return
                if "oci-layout" in names:
                    raise ValueError("invalid_image")
                for item in t:
                    name = safe_name(item.name)
                    if item.isdir():
                        continue
                    if not item.isfile():
                        raise ValueError("unsafe_archive")
                    self.entry(label+"!/"+name if image else name, self._read(t.extractfile(item), item.size), depth+1, image)

    def entry(self, path, raw, depth=0, image=False):
        if depth>5:
            raise ValueError("scan_limit")
        self.name_check(path)
        parts = path.split("/")
        if not image and len(parts)>1 and parts[0].startswith("MoonUESTC-"):
            path="/".join(parts[1:])
        self.data(path, raw, image=image)
        factory=None
        if raw.startswith(b"\x1f\x8b"):
            factory=lambda stream,mode: gzip.GzipFile(fileobj=stream,mode=mode)
        elif raw.startswith(b"\xfd7zXZ\x00"):
            factory=lzma.LZMAFile
        elif raw.startswith(b"BZh"):
            factory=bz2.BZ2File
        if factory:
            with factory(io.BytesIO(raw),mode="rb") as stream:
                content=self._read(stream)
            self.entry(path+".decompressed",content,depth+1,image)
        elif raw.startswith(b"PK\x03\x04") or (len(raw)>262 and raw[257:262]==b"ustar"):
            self.archive(raw,path,depth,image)

    def docker_archive(self, archive, label):
        manifest = json.load(archive.extractfile("manifest.json"))
        if not isinstance(manifest, list) or not manifest:
            raise ValueError("invalid_image")
        members=archive.getmembers()
        member_names=[m.name for m in members]
        if len(member_names)!=len(set(member_names)):
            raise ValueError("invalid_image")
        used={"manifest.json"}
        layers = set()
        for image in manifest:
            config_name = safe_name(image["Config"])
            used.add(config_name)
            config_raw = self._read(archive.extractfile(config_name))
            config = json.loads(config_raw)
            self.data("image-config.json", config_raw, image=True)
            if not isinstance(config.get("config"), dict):
                raise ValueError("invalid_image")
            env = "\n".join(config["config"].get("Env") or []).encode()
            self.data("image-environment", env, image=True)
            for layer in image["Layers"]:
                layer = safe_name(layer)
                if layer in layers:
                    continue
                layers.add(layer)
                used.add(layer)
                source = archive.extractfile(layer)
                with tarfile.open(fileobj=source, mode="r|*") as contents:
                    for item in contents:
                        if item.isdir():
                            continue
                        name = safe_name(item.name)
                        if item.isdev():
                            continue
                        if item.issym() or item.islnk():
                            target = item.linkname.replace("\\", "/")
                            resolved = posixpath.normpath(target.lstrip("/") if target.startswith("/") else posixpath.join(posixpath.dirname(name), target))
                            if resolved.startswith("../") or path_rule(resolved, image=True):
                                raise ValueError("unsafe_archive")
                            continue
                        if not item.isfile():
                            raise ValueError("unsafe_archive")
                        self.entry(name, self._read(contents.extractfile(item), item.size), image=True)
                self.layers += 1
        for member in members:
            if member.isdir() or member.name in used:
                continue
            if not member.isfile():
                raise ValueError("invalid_image")
            name=safe_name(member.name)
            raw=self._read(archive.extractfile(member),member.size)
            # Extra OCI indexes/manifests are JSON. Do not silently skip an orphan blob.
            try:
                json.loads(raw)
            except (ValueError,UnicodeError):
                raise ValueError("invalid_image") from None
            self.data(name,raw,image=True)

    def file(self, path):
        p = Path(path)
        self.name_check(p.name)
        if not p.is_file() or p.is_symlink():
            raise ValueError("scan_error")
        if p.stat().st_size > MAX_TOTAL:
            raise ValueError("scan_limit")
        if p.name.endswith((".zip", ".tar", ".tar.gz", ".tgz")):
            self.archive(p.read_bytes(), p.name)
        else:
            with p.open("rb") as stream:
                self.entry(p.name, self._read(stream, p.stat().st_size))

    def tree(self, root):
        root = Path(root).resolve()
        names = run_git(root, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")
        for name in sorted(set(x for x in names if x)):
            rel = safe_name(name)
            p = root / rel
            if p.is_symlink() or not p.is_file() or not p.resolve().is_relative_to(root):
                raise ValueError("scan_error")
            with p.open("rb") as stream:
                self.data(rel, self._read(stream, p.stat().st_size))

    def history(self, root, refs):
        rows = run_git(root, "rev-list", "--objects", *refs, "--").decode().splitlines()
        paths = {}
        for row in rows:
            pair = row.split(" ", 1)
            paths[pair[0]] = pair[1] if len(pair)>1 else None
        for ref in refs:
            oid=run_git(root,"rev-parse",ref).decode().strip()
            paths.setdefault(oid,None)
        info = run_git(root, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                       data=("\n".join(paths)+"\n").encode()).decode().splitlines()
        blobs = []
        for row in info:
            oid, kind, size = row.split()
            if kind in ("blob","commit","tag","tree"):
                if int(size) > MAX_FILE:
                    raise ValueError("scan_limit")
                blobs.append(oid)
        output = run_git(root, "cat-file", "--batch", data=("\n".join(blobs)+"\n").encode()) if blobs else b""
        offset = 0
        for oid in blobs:
            end = output.index(b"\n", offset)
            size = int(output[offset:end].split()[2])
            kind=output[offset:end].split()[1]
            raw = output[end+1:end+1+size];offset = end+size+2
            name=paths[oid] or ("git-object/"+oid)
            if kind==b"tree":
                for entry in run_git(root,"ls-tree","-z",oid).split(b"\0"):
                    if not entry:
                        continue
                    filename=entry.split(b"\t",1)[1].decode()
                    if path_rule(filename):
                        self.finding("private_runtime_path","git-tree/"+oid+"/"+filename)
                self.data(name,raw)
            elif kind==b"blob":
                self.entry(name,raw)
            else:
                self.data(name,raw)

    def report(self):
        findings = [{"rule": f["rule"], "file_id": hashlib.sha256(f["path"].encode()).hexdigest()[:16]} for f in self.findings]
        return {"passed": not findings, "files_checked": self.files, "image_layers_checked": self.layers,
                "findings": findings, "reviewed_examples_matched": len(self.waived),
                "matched_values_logged": False}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--root",type=Path)
    p.add_argument("--ref",action="append",default=[])
    p.add_argument("--artifact",type=Path,action="append",default=[])
    p.add_argument("--private-markers",type=Path)
    p.add_argument("--allowlist",type=Path,default=Path(__file__).with_name("privacy-allowlist.json"))
    a=p.parse_args(argv)
    try:
        markers=json.loads(a.private_markers.read_text(encoding="utf-8")) if a.private_markers else []
        scanner=Scanner(a.allowlist,markers)
        if not a.root and not a.artifact:
            raise ValueError("scan_error")
        if a.root:
            scanner.tree(a.root)
            scanner.history(a.root,a.ref or ["HEAD"])
        for artifact in a.artifact:
            scanner.file(artifact)
        result=scanner.report()
    except Exception:
        result={"passed":False,"findings":[{"rule":"scan_error"}],"matched_values_logged":False}
    print(json.dumps(result))
    return 0 if result["passed"] else 1

if __name__ == "__main__":
    raise SystemExit(main())
