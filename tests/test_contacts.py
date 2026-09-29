import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET
from unittest import mock
from wechat_ai_exporter.contacts import read_contacts, export_contacts, csv_cell
from wechat_ai_exporter.cli import main

class ContactTests(unittest.TestCase):
    def fixture(self,root):
        p=root/'contacts.db'
        con=sqlite3.connect(p)
        con.execute('CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT,phone TEXT)')
        con.executemany('INSERT INTO contact VALUES(?,?,?,?,?)',[
          ('wxid_1','=1+1','备注','alias1','secret-phone'),
          ('wxid_1','=1+1','备注','alias1','secret-phone'),
          ('123@chatroom','群名','','','secret-phone'),
          ('gh_a','号','','','secret-phone'),('filehelper','助手','','','secret-phone')])
        con.commit();con.close();return p
    def test_export_classification_and_safety(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=self.fixture(root);before=p.read_bytes()
            result=export_contacts(p,root/'out',scope='all')
            self.assertEqual(result['exact_duplicates_removed'],1)
            self.assertEqual(sum(result['counts'].values()),4)
            self.assertFalse(result['friendship_verified'])
            self.assertEqual(p.read_bytes(),before)
            with zipfile.ZipFile(result['archive']) as z:
                self.assertIn("'=1+1",z.read('其他联系人.csv').decode('utf-8-sig'))
                self.assertNotIn(b'secret-phone',b''.join(z.read(n) for n in z.namelist()))
                with zipfile.ZipFile(io.BytesIO(z.read('全部缓存账号.xlsx'))) as x:
                    for n in x.namelist(): ET.fromstring(x.read(n))
                    self.assertNotIn(b'<f>',x.read('xl/worksheets/sheet1.xml'))
                    self.assertNotIn(b'wxid_1',x.read('xl/worksheets/sheet1.xml'))
    def test_requires_consent_before_probe(self):
        with mock.patch('wechat_ai_exporter.cli.probe_database_key') as probe:
            self.assertEqual(main(['export-contacts-auto-key','--contact-database','none','--output-dir','none']),4)
            probe.assert_not_called()
    def test_formula_whitespace(self):
        self.assertEqual(csv_cell('  =1'),"'  =1")
        self.assertEqual(csv_cell('张三'),'张三')
    def test_unknown_schema_fails(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'test.db';sqlite3.connect(p).close()
            with self.assertRaises(Exception):read_contacts(p)

    def test_friend_filter_is_conservative(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'contact.db'
            con=sqlite3.connect(p)
            con.execute('CREATE TABLE contact(username TEXT,nick_name TEXT,remark TEXT,alias TEXT,local_type INTEGER,flag INTEGER,delete_flag INTEGER,verify_flag INTEGER)')
            cases=[('friend',1,3,0,0),('friend_bits',1,515,0,0),
                   ('member',3,4,0,0),('member_conflict',3,3,0,0),
                   ('deleted',1,3,1,0),('unknown',None,3,0,0),
                   ('null_flag',1,None,0,0),('one_bit',1,1,0,0),
                   ('negative',1,-1,0,0),('enterprise',5,3,0,0),
                   ('verified',1,3,0,24),('gh_public',1,3,0,0),
                   ('1@chatroom',1,3,0,0),('filehelper',1,3,0,0)]
            con.executemany('INSERT INTO contact VALUES(?,?,?,?,?,?,?,?)',
                            [(n,n,'has remark','',lt,f,d,v) for n,lt,f,d,v in cases])
            con.commit();con.close()
            rows,_=read_contacts(p)
            self.assertEqual({r[1] for r in rows},{'friend','friend_bits'})
            result=export_contacts(p,Path(t)/'out')
            self.assertEqual(result['scope'],'friends')
            with zipfile.ZipFile(result['archive']) as z:
                self.assertNotIn('其他联系人.csv',z.namelist())
                self.assertIn('微信联系人.csv',z.namelist())
                self.assertIn('微信联系人.xlsx',z.namelist())
                self.assertFalse(any(n.endswith('.xls') for n in z.namelist()))

    def test_missing_relationship_fields_fail_closed(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);p=self.fixture(root)
            with self.assertRaises(Exception):export_contacts(p,root/'out')
            self.assertFalse((root/'out').exists())
