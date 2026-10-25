"""Synthetic canaries only. No production inventory or school requests."""
import base64
import bz2
import lzma
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode=True
SCRIPTS=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SCRIPTS))
import privacy_scan as privacy
import release_guard as guard

def tar_bytes(entries):
    out=io.BytesIO()
    with tarfile.open(fileobj=out,mode="w") as t:
        for name,value in entries:
            info=tarfile.TarInfo(name)
            if isinstance(value,tuple):
                info.type=tarfile.SYMTYPE;info.linkname=value[0];t.addfile(info)
            else:
                info.size=len(value);t.addfile(info,io.BytesIO(value))
    return out.getvalue()

def image_bytes(layers,env=()):
    items=[("config.json",json.dumps({"config":{"Env":list(env)}}).encode())]
    refs=[]
    for n,layer in enumerate(layers):
        name="layer"+str(n)+"/layer.tar";refs.append(name);items.append((name,layer))
    items.append(("manifest.json",json.dumps([{"Config":"config.json","Layers":refs}]).encode()))
    return tar_bytes(items)

def token():
    return b"ghp_"+b"Z"*36

class PrivacyTests(unittest.TestCase):
    def scan(self,raw,path="example.txt",markers=()):
        s=privacy.Scanner(markers=markers);s.data(path,raw);return s

    def test_placeholders_are_allowed(self):
        s=self.scan(json.dumps({"password":"PUT_YOUR_PASSWORD_HERE","student_id":"PUT_YOUR_STUDENT_ID_HERE"}).encode())
        self.assertTrue(s.report()["passed"])

    def test_real_looking_credentials_block(self):
        for field in ("password","browser_fingerprint","username","student_id","access_token"):
            with self.subTest(field=field):
                s=self.scan(json.dumps({field:"synthetic-value-not-a-placeholder"}).encode())
                self.assertFalse(s.report()["passed"])

    def test_private_paths_block_even_empty(self):
        for path in (".env","data/empty","config/settings.json","backups/copy","dashboard.key","session.lwp"):
            with self.subTest(path=path):
                self.assertFalse(self.scan(b"",path).report()["passed"])

    def test_renamed_database_blocked_by_magic(self):
        s=self.scan(b"SQLite format 3"+b"\0"+b"synthetic","photo.jpg")
        self.assertIn("database_content",[f["rule"] for f in s.findings])

    def test_cookie_and_encrypted_stores_block(self):
        for raw in (b"#LWP-"+b"Cookies-2.0",b"# Netscape HTTP "+b"Cookie File",b"MW"+b"1"+b"X"*40):
            self.assertFalse(self.scan(raw).report()["passed"])

    def test_private_key_complete_and_fragment(self):
        header=b"-----BEGIN "+b"PRIVATE KEY-----"
        end=b"-----END "+b"PRIVATE KEY-----"
        for raw in (header,header+b"\nYWJj\n"+end):
            self.assertFalse(self.scan(raw).report()["passed"])

    def test_tokens_and_cookie_headers(self):
        for raw in (token(),b"Cookie"+b": SID=synthetic-session-value",b"Authorization"+b": Bearer synthetic-token"):
            self.assertFalse(self.scan(raw).report()["passed"])

    def test_encoded_known_values_block_anywhere(self):
        marker="synthetic-private-canary-9841"
        for raw in (marker.encode(),base64.b64encode(marker.encode()),marker.encode().hex().encode()):
            s=self.scan(raw,markers=[marker])
            self.assertIn("private_marker",[x["rule"] for x in s.findings])

    def test_reports_do_not_echo_value_or_private_path(self):
        raw=token();s=self.scan(raw,"real-person@example.invalid.txt")
        output=json.dumps(s.report()).encode()
        self.assertNotIn(raw,output);self.assertNotIn(b"real-person",output)
        self.assertFalse(s.report()["matched_values_logged"])

    def test_allowlist_binds_full_value(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/"allow.json";raw=token();s=self.scan(raw)
            one=s.findings[0]
            a.write_text(json.dumps({"version":1,"exceptions":[one|{"reason":"synthetic test"}]}))
            allowed=privacy.Scanner(a);allowed.data("example.txt",raw)
            self.assertTrue(allowed.report()["passed"])
            changed=privacy.Scanner(a);changed.data("example.txt",raw+b"A")
            self.assertFalse(changed.report()["passed"])

    def test_real_private_markers_cannot_be_waived(self):
        with tempfile.TemporaryDirectory() as tmp:
            a=Path(tmp)/"allow.json"
            a.write_text(json.dumps({"version":1,"exceptions":[{"rule":"private_marker","path":"x","match_sha256":"0"*64,"reason":"invalid"}]}))
            with self.assertRaises(ValueError):privacy.Scanner(a)

    def test_nested_archives_are_scanned(self):
        inner=tar_bytes([("hidden.txt",token())])
        out=io.BytesIO()
        with zipfile.ZipFile(out,"w") as z:z.writestr("nested.tar.gz",gzip.compress(inner))
        s=privacy.Scanner();s.archive(out.getvalue(),"outer.zip")
        self.assertFalse(s.report()["passed"])

    def test_archive_traversal_and_links_reject(self):
        for entries in ([("../outside",b"x")],[("link",("../outside",))]):
            with self.assertRaises(ValueError):privacy.Scanner().archive(tar_bytes(entries),"x.tar")

    def test_every_image_layer_including_removed_files(self):
        raw=image_bytes([tar_bytes([("tmp/old.txt",token())]),tar_bytes([("tmp/.wh.old.txt",b"")])])
        s=privacy.Scanner();s.archive(raw,"image.tar")
        self.assertEqual(s.layers,2);self.assertFalse(s.report()["passed"])

    def test_image_runtime_environment_scanned(self):
        raw=image_bytes([tar_bytes([("app/ok.py",b"pass")])],["password="+chr(34)+"synthetic-private-value"+chr(34)])
        s=privacy.Scanner();s.archive(raw,"image.tar")
        self.assertFalse(s.report()["passed"])

    def test_image_private_mount_contents_block(self):
        s=privacy.Scanner();s.archive(image_bytes([tar_bytes([("data/any",b"x")])]),"image.tar")
        self.assertIn("private_runtime_path",[x["rule"] for x in s.findings])

    def test_truncated_and_unknown_image_fail_closed(self):
        for raw in (b"not a tar",image_bytes([b"corrupt layer"])):
            with self.assertRaises(Exception):privacy.Scanner().archive(raw,"image.tar")

    def test_scan_limits_fail_closed(self):
        with patch.object(privacy,"MAX_FILE",3):
            with self.assertRaises(ValueError):self.scan(b"1234")

    def test_missing_artifact_blocks(self):
        with self.assertRaises(ValueError):privacy.Scanner().file("/does-not-exist/privacy-test")

    def test_removed_git_secret_remains_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);self.git(repo,"init","-q")
            self.git(repo,"config","user.name","Synthetic");self.git(repo,"config","user.email","synthetic@example.invalid")
            f=repo/"notes.txt";f.write_bytes(token());self.git(repo,"add",".");self.git(repo,"commit","-qm","synthetic canary")
            f.write_text("clean");self.git(repo,"add",".");self.git(repo,"commit","-qm","remove")
            s=privacy.Scanner();s.history(repo,["HEAD"]);self.assertFalse(s.report()["passed"])

    def test_ssh_failure_blocks_and_hides_stderr(self):
        result=subprocess.CompletedProcess([],1,b"",b"synthetic confidential error")
        with patch.object(guard,"setting",side_effect=lambda k:{"privacyHost":"fixture","privacyContainer":"fixture"}.get(k,"")),patch.object(guard.subprocess,"run",return_value=result):
            with self.assertRaises(ValueError):guard.live_markers()

    def test_unquoted_image_environment_is_blocked(self):
        raw=image_bytes([tar_bytes([("app/ok.py",b"pass")])],["MOON_PASSWORD=synthetic-value"])
        scanner=privacy.Scanner();scanner.archive(raw,"image.tar")
        self.assertIn("credential_environment",[x["rule"] for x in scanner.findings])

    def test_tiny_passwords_are_not_treated_as_placeholders(self):
        raw=json.dumps({"password":"q"}).encode()
        self.assertFalse(self.scan(raw).report()["passed"])

    def test_changed_private_key_cannot_use_a_fixture_exception(self):
        head=b"-----BEGIN "+b"PRIVATE KEY-----\n"
        end=b"\n-----END "+b"PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as tmp:
            raw=head+b"YWJj"+end;s=self.scan(raw)
            allow=Path(tmp)/"allow.json"
            allow.write_text(json.dumps({"version":1,"exceptions":[f|{"reason":"synthetic fixture"} for f in s.findings]}))
            changed=privacy.Scanner(allow);changed.data("example.txt",head+b"ZGVm"+end)
            self.assertFalse(changed.report()["passed"])

    def test_private_inventory_is_reloaded_each_time(self):
        protocol=json.dumps({"schema":1,"read_only":True,"markers_b64":[base64.b64encode(b"synthetic-inventory-value").decode()]}).encode()
        answer=subprocess.CompletedProcess([],0,protocol,b"")
        config=lambda key:{"privacyHost":"fixture","privacyContainer":"fixture","privacyMarkers":""}.get(key,"")
        with patch.object(guard,"setting",side_effect=config),patch.object(guard.subprocess,"run",return_value=answer) as fake:
            guard.live_markers();guard.live_markers()
            self.assertEqual(fake.call_count,2)

    def test_user_csv_export_and_unsupported_compression_block(self):
        raw=("username"+",password_hash\nfixture,synthetic-value").encode()
        self.assertFalse(self.scan(raw).report()["passed"])
        with self.assertRaises(ValueError):self.scan(bytes.fromhex("377abcaf271c")+b"opaque")

    def test_unreferenced_image_blob_is_not_silently_skipped(self):
        raw=image_bytes([tar_bytes([("app/ok.py",b"pass")])])
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            entries=[(m.name,archive.extractfile(m).read()) for m in archive if m.isfile()]
        entries.append(("orphan.blob",b"opaque encrypted archive"))
        with self.assertRaises(ValueError):privacy.Scanner().archive(tar_bytes(entries),"image.tar")

    def test_private_identifier_in_filename_is_blocked(self):
        marker="synthetic-identifier-9741"
        scanner=self.scan(b"clean",marker+".txt",markers=[marker])
        self.assertFalse(scanner.report()["passed"])

    def test_compressed_file_inside_image_is_not_opaque(self):
        for compressor in (gzip.compress,lzma.compress,bz2.compress):
            with self.subTest(compressor=compressor):
                raw=image_bytes([tar_bytes([("usr/share/doc/canary.bin",compressor(token()))])])
                scanner=privacy.Scanner();scanner.archive(raw,"image.tar")
                self.assertFalse(scanner.report()["passed"])

    def test_fragment_beside_complete_fixture_is_still_blocked(self):
        header=b"-----BEGIN "+b"PRIVATE KEY-----\n"
        end=b"\n-----END "+b"PRIVATE KEY-----"
        with tempfile.TemporaryDirectory() as tmp:
            full=header+b"YWJj"+end;s=self.scan(full)
            allow=Path(tmp)/"allow.json"
            allow.write_text(json.dumps({"version":1,"exceptions":[f|{"reason":"synthetic"} for f in s.findings]}))
            checked=privacy.Scanner(allow);checked.data("example.txt",full+b"\n"+header+b"partial")
            self.assertIn("private_key_fragment",[f["rule"] for f in checked.findings])

    def test_private_directory_case_does_not_bypass(self):
        self.assertFalse(self.scan(b"clean","CONFIG/private.json").report()["passed"])

    def test_archived_secret_removed_from_history_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);self.git(repo,"init","-q");self.git(repo,"config","user.name","Synthetic")
            self.git(repo,"config","user.email","synthetic@example.invalid")
            out=io.BytesIO()
            with zipfile.ZipFile(out,"w",zipfile.ZIP_DEFLATED) as z:z.writestr("note.txt",token())
            (repo/"hidden.bin").write_bytes(out.getvalue());self.git(repo,"add",".");self.git(repo,"commit","-qm","archive")
            (repo/"hidden.bin").unlink();self.git(repo,"add","-u");self.git(repo,"commit","-qm","remove")
            scanner=privacy.Scanner();scanner.history(repo,["HEAD"])
            self.assertFalse(scanner.report()["passed"])

    def test_private_path_with_shared_blob_in_history_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo=Path(tmp);self.git(repo,"init","-q");self.git(repo,"config","user.name","Synthetic")
            self.git(repo,"config","user.email","synthetic@example.invalid")
            (repo/"safe.txt").write_text("same");(repo/".env").write_text("same")
            self.git(repo,"add",".");self.git(repo,"commit","-qm","shared blob")
            (repo/".env").unlink();self.git(repo,"add","-u");self.git(repo,"commit","-qm","remove")
            scanner=privacy.Scanner();scanner.history(repo,["HEAD"])
            self.assertIn("private_runtime_path",[f["rule"] for f in scanner.findings])

    @staticmethod
    def git(repo,*args,env=None):
        return subprocess.run(["git","-C",str(repo),*args],capture_output=True,text=True,env=env,check=True).stdout.strip()

    def test_actual_git_pre_push_blocks_before_remote_update(self):
        with tempfile.TemporaryDirectory() as tmp:
            top=Path(tmp);repo=top/"repo";repo.mkdir();remote=top/"remote.git"
            self.git(repo,"init","-q");self.git(repo,"config","user.name","Synthetic");self.git(repo,"config","user.email","synthetic@example.invalid")
            subprocess.run(["git","init","--bare","-q",str(remote)],check=True,capture_output=True)
            (repo/"scripts").mkdir();(repo/".githooks").mkdir()
            for name in ("privacy_scan.py","release_guard.py","collect_private_inventory.py","guarded-publish.py"):
                shutil.copy2(SCRIPTS/name,repo/"scripts"/name)
            (repo/"scripts/privacy-allowlist.json").write_text(json.dumps({"version":1,"exceptions":[]}))
            shutil.copy2(SCRIPTS.parent/".githooks/pre-push",repo/".githooks/pre-push")
            (repo/".githooks/pre-push").chmod(0o755)
            stub=top/"bin";stub.mkdir()
            marker=b"synthetic-live-canary-9613"
            protocol={"schema":1,"markers_b64":[base64.b64encode(marker).decode()],"read_only":True}
            (stub/"ssh").write_text("#!"+sys.executable+"\nimport sys\nsys.stdin.read()\nprint("+repr(json.dumps(protocol))+")\n");(stub/"ssh").chmod(0o755)
            executable=stub/'ssh'
            if sys.platform=='win32':
                (stub/'stub-ssh.py').write_text('import sys\nsys.stdin.read()\nprint('+repr(json.dumps(protocol))+')\n')
                executable=stub/'ssh.cmd'
                executable.write_text('@echo off\n"'+sys.executable+'" "'+str(stub/'stub-ssh.py')+'"\n')
            for k,v in [("core.hooksPath",".githooks"),("moonuestc.privacyPython",sys.executable),("moonuestc.privacyHost","fixture"),("moonuestc.privacyContainer","fixture")]:self.git(repo,"config",k,v)
            self.git(repo,'config','moonuestc.privacySSH',str(executable))
            self.git(repo,"remote","add","origin",str(remote));self.git(repo,"add",".");self.git(repo,"commit","-qm","clean")
            env=os.environ.copy();env["PATH"]=str(stub)+os.pathsep+env["PATH"];env["PYTHONDONTWRITEBYTECODE"]="1"
            clean=subprocess.run(["git","-C",str(repo),"push","origin","HEAD:refs/heads/main"],capture_output=True,text=True,env=env)
            self.assertEqual(clean.returncode,0,clean.stderr)
            before=self.git(remote,"rev-parse","refs/heads/main")
            callback=top/"upload-callback"
            command=[sys.executable,str(repo/"scripts/guarded-publish.py"),"--",sys.executable,"-c","from pathlib import Path; Path("+repr(str(callback))+").touch()"]
            good=subprocess.run(command,capture_output=True,text=True,env=env)
            self.assertEqual(good.returncode,0,good.stdout)
            self.assertTrue(callback.exists());callback.unlink()
            (repo/"leak.txt").write_bytes(base64.b64encode(marker));self.git(repo,"add",".");self.git(repo,"commit","-qm","synthetic leak")
            bad=subprocess.run(["git","-C",str(repo),"push","origin","HEAD:refs/heads/main"],capture_output=True,text=True,env=env)
            self.assertNotEqual(bad.returncode,0)
            self.assertEqual(self.git(remote,"rev-parse","refs/heads/main"),before)
            self.assertNotIn(marker.decode(),bad.stdout+bad.stderr)
            blocked=subprocess.run(command,capture_output=True,text=True,env=env)
            self.assertNotEqual(blocked.returncode,0)
            self.assertFalse(callback.exists())

if __name__=="__main__":
    unittest.main()
