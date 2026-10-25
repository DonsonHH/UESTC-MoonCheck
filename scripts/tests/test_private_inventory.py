"""The release gate must recognize nested, encrypted OAuth credentials."""
import base64
from contextlib import closing
import importlib.util
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]))
from moonuestc.vault import Vault


class OAuthInventory(unittest.TestCase):
    def test_live_inventory_covers_oauth_identifiers_and_tokens_without_writing_them(self):
        source=Path(__file__).resolve().parents[1]/'collect_private_inventory.py'
        spec=importlib.util.spec_from_file_location('private_inventory_under_test',source)
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);vault=Vault(root)
            values={name:'synthetic-wx-'+name+'-canary' for name in ('openid','accesstoken','refreshtoken','school_user_id')}
            account={'student_id':'synthetic-student-canary','password':'synthetic-password-canary',
                     'wechat_authorization':{'school_user_id':values['school_user_id'],
                                             'credentials':{key:values[key] for key in ('openid','accesstoken','refreshtoken')}}}
            with closing(sqlite3.connect(root/'dashboard.sqlite3')) as db:
                db.executescript('CREATE TABLE web_users(username,display_name,password_hash,role);'
                    'CREATE TABLE web_accounts(id,payload);CREATE TABLE web_cookies(binding,payload);'
                    'CREATE TABLE web_sessions(token_hash,csrf);')
                db.execute('INSERT INTO web_accounts VALUES(?,?)',('synthetic-account',vault.seal(account,'account:synthetic-account')))
                db.commit()
            with patch.dict(os.environ,{'MOON_DATA':str(root),'MOON_CONFIG':str(root/'missing-config.json')}):
                report=collector.collect()
            markers={base64.b64decode(value).decode(errors='replace') for value in report['markers_b64']}
            self.assertTrue(set(values.values())<=markers)
            self.assertTrue(report['read_only']);self.assertFalse(report['plaintext_written_to_disk'])
            for path in root.iterdir():
                if path.is_file():
                    for value in values.values():self.assertNotIn(value.encode(),path.read_bytes())


if __name__=='__main__':unittest.main()
