#!/usr/bin/env python3
"""One mandatory preflight for Git pushes and release uploads."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

sys.dont_write_bytecode=True
from privacy_scan import Scanner,run_git

ROOT=Path(__file__).resolve().parents[1]

def setting(name):
    p=subprocess.run(["git","-C",str(ROOT),"config","--get","moonuestc."+name],capture_output=True,text=True)
    if p.returncode not in (0,1):
        raise ValueError("configuration_unavailable")
    return p.stdout.strip()

def ssh_executable():
    configured=setting("privacySSH")
    if configured:
        return configured
    if sys.platform=="win32":
        native=Path(os.environ.get("SystemRoot","C:/Windows"))/"System32/OpenSSH/ssh.exe"
        if native.is_file():
            return str(native)
    resolved=shutil.which("ssh")
    if not resolved:
        raise ValueError("private_inventory_unavailable")
    return resolved

def live_markers():
    host=setting("privacyHost");container=setting("privacyContainer")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*",host) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*",container):
        raise ValueError("private_inventory_not_configured")
    source=Path(__file__).with_name("collect_private_inventory.py").read_bytes()
    child=subprocess.run([ssh_executable(),"-o","BatchMode=yes","-o","ConnectTimeout=15",host,
                          "docker exec -i "+container+" python -"],
                         input=source,capture_output=True,timeout=45)
    if child.returncode or len(child.stdout)>8*1024*1024:
        raise ValueError("private_inventory_unavailable")
    value=json.loads(child.stdout)
    if value.get("schema")!=1 or value.get("read_only") is not True or not value.get("markers_b64"):
        raise ValueError("private_inventory_invalid")
    result=[base64.b64decode(v,validate=True) for v in value["markers_b64"]]
    if any(len(v)<6 for v in result):
        raise ValueError("private_inventory_invalid")
    private=setting("privacyMarkers")
    if private:
        extra=json.loads(Path(private).read_text(encoding="utf-8"))
        if not isinstance(extra,list) or not all(isinstance(v,str) and v for v in extra):
            raise ValueError("private_inventory_invalid")
        result.extend(extra)
    return result

def preflight(refs,artifacts=(),ci=False,payload=None,payload_name="release-payload"):
    markers=[] if ci else live_markers()
    scanner=Scanner(ROOT/"scripts/privacy-allowlist.json",markers)
    scanner.tree(ROOT)
    scanner.history(ROOT,refs or ["HEAD"])
    for path in artifacts:
        scanner.file(path)
    if payload is not None:
        scanner.entry(payload_name,payload)
    result=scanner.report()
    result.update(live_private_inventory_checked=not ci,private_values_uploaded=False)
    return result

def install(args):
    previous=subprocess.run(["git","-C",str(ROOT),"config","--get","core.hooksPath"],capture_output=True,text=True).stdout.strip()
    if previous and previous!=".githooks":
        raise ValueError("existing_hook_configuration")
    for name,value in [("privacyHost",args.host),("privacyContainer",args.container),
                       ("privacyPython",args.python or sys.executable),("privacySSH",ssh_executable())]:
        if not value:
            raise ValueError("missing_configuration")
        subprocess.run(["git","-C",str(ROOT),"config","moonuestc."+name,value],check=True,capture_output=True)
    if args.private_markers:
        subprocess.run(["git","-C",str(ROOT),"config","moonuestc.privacyMarkers",str(Path(args.private_markers).resolve())],check=True,capture_output=True)
    subprocess.run(["git","-C",str(ROOT),"config","core.hooksPath",".githooks"],check=True,capture_output=True)
    return {"passed":True,"pre_push_hook_installed":True,"configuration_scope":"local Git only"}

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="command",required=True)
    check=sub.add_parser("check");check.add_argument("--ref",action="append",default=[])
    check.add_argument("--artifact",type=Path,action="append",default=[])
    check.add_argument("--artifact-list",type=Path)
    check.add_argument("--payload-stdin",action="store_true");check.add_argument("--payload-name",default="release-payload")
    check.add_argument("--ci",action="store_true",help="Generic CI scan; no production data or SSH keys in GitHub.")
    push=sub.add_parser("pre-push");push.add_argument("remote",nargs="?");push.add_argument("url",nargs="?")
    setup=sub.add_parser("install");setup.add_argument("--host",required=True);setup.add_argument("--container",required=True)
    setup.add_argument("--private-markers",type=Path);setup.add_argument("--python")
    a=p.parse_args(argv)
    try:
        if a.command=="install":
            result=install(a)
        elif a.command=="pre-push":
            refs=[]
            for line in sys.stdin:
                parts=line.split()
                if len(parts)!=4 or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}",parts[1]):
                    raise ValueError("invalid_push_protocol")
                if set(parts[1])!={"0"}:
                    refs.append(parts[1])
            result=preflight(refs)
        else:
            paths=list(a.artifact)
            if a.artifact_list:
                paths.extend(Path(v) for v in json.loads(a.artifact_list.read_text(encoding="utf-8")))
            result=preflight(a.ref,paths,a.ci,
                             sys.stdin.buffer.read() if a.payload_stdin else None,a.payload_name)
    except Exception as error:
        categories={"private_inventory_not_configured","private_inventory_unavailable","private_inventory_invalid",
                    "configuration_unavailable","git_read_failed","scan_error","unsafe_archive","scan_limit",
                    "invalid_image","unsupported_archive"}
        category=str(error) if str(error) in categories else "check_failed"
        result={"passed":False,"findings":[{"rule":"privacy_gate_unavailable","stage":category}],
                "matched_values_logged":False,"release_stopped":True}
    print(json.dumps(result))
    if not result["passed"]:
        sys.stderr.write("Privacy gate rejected publication. Values are hidden. No upload is allowed.\n")
    return 0 if result["passed"] else 1

if __name__=="__main__":
    raise SystemExit(main())
