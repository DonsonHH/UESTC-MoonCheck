#!/usr/bin/env python3
"""Run a GitHub/GHCR mutation only after the mandatory private preflight."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
from release_guard import preflight

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ref",action="append",default=[])
    p.add_argument("--artifact",type=Path,action="append",default=[])
    p.add_argument("--artifact-list",type=Path)
    p.add_argument("command",nargs=argparse.REMAINDER)
    a=p.parse_args()
    try:
        artifacts=list(a.artifact)
        if a.artifact_list:
            artifacts.extend(Path(x) for x in json.loads(a.artifact_list.read_text(encoding="utf-8")))
        command=a.command[1:] if a.command[:1]==["--"] else a.command
        if not command:
            raise ValueError()
        result=preflight(a.ref,artifacts)
        print(json.dumps(result),flush=True)
        if not result["passed"]:
            return 1
    except Exception:
        print(json.dumps({"passed":False,"release_stopped":True,"matched_values_logged":False}))
        return 1
    return subprocess.run(command).returncode

if __name__=="__main__":
    raise SystemExit(main())
