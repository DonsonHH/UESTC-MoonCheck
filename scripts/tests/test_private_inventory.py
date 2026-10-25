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
    def test_encrypted_qq_credentials_and_class_mapping_are_live_private_markers(self):
        source=Path(__file__).resolve().parents[1]/'collect_private_inventory.py'
        spec=importlib.util.spec_from_file_location('private_support_inventory',source)
        collector=importlib.util.module_from_spec(spec);spec.loader.exec_module(collector)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);vault=Vault(root)
            with closing(sqlite3.connect(root/'dashboard.sqlite3')) as db:
                db.executescript('CREATE TABLE web_users(username,display_name,password_hash,role);CREATE TABLE web_accounts(id,payload);'
                    'CREATE TABLE web_cookies(binding,payload);CREATE TABLE web_sessions(token_hash,csrf);'
                    'CREATE TABLE web_support_settings(name,payload);CREATE TABLE web_qq_contacts(digest,payload);')
                bot={'app_id':'synthetic-app-id-canary','app_secret':'synthetic-bot-secret-canary','callback_key':'synthetic-callback-key-canary'}
                cadre={'class_key':'synthetic-class-key-canary','targets':['synthetic-student-id-canary'],
                    'members':{'synthetic-student-id-canary':'synthetic-member-id-canary'},'group_openid':'synthetic-group-id-canary'}
                for name,value in (('qq_bot',bot),('cadre:synthetic-account',cadre)):
                    db.execute('INSERT INTO web_support_settings VALUES(?,?)',(name,vault.seal(value,'support:'+name)))
                contact={'target':'synthetic-contact-group-canary','sender':'synthetic-contact-member-canary'}
                db.execute('INSERT INTO web_qq_contacts VALUES(?,?)',('synthetic-contact',vault.seal(contact,'qq_contact:synthetic-contact')));db.commit()
            with patch.dict(os.environ,{'MOON_DATA':str(root),'MOON_CONFIG':str(root/'missing-config.json')}):report=collector.collect()
            markers={base64.b64decode(value).decode(errors='replace') for value in report['markers_b64']}
            expected=set(bot.values())|set(contact.values())|{'synthetic-class-key-canary','synthetic-student-id-canary','synthetic-member-id-canary','synthetic-group-id-canary'}
            self.assertTrue(expected<=markers)
            for path in root.iterdir():
                if path.is_file():
                    for value in expected:self.assertNotIn(value.encode(),path.read_bytes())

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
