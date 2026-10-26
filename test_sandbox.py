import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import HTTPException
import test_backend as backend
import sandbox


class SandboxTests(unittest.TestCase):
    def setUp(self):
        backend.BackendTests.setUp(self)

    def action(self,tool,**args):
        return self.client.post('/api/actions',headers=self.agent,json={'session_id':self.session,'tool':tool,'args':args})

    def allow(self,*tools):
        with backend.app.db() as c:
            c.execute('UPDATE policies SET rules_json=? WHERE id=?',(json.dumps({'name':'sandbox-test','rules':[{'tool':t,'action':'allow'} for t in tools],'default':'block'}),'default-assistant'))

    def test_seed_listing_and_isolated_agent_directories(self):
        result=self.action('list_files',dir='.').json()['result']
        names={entry['name'] for entry in result['entries']}
        self.assertTrue({'customers.csv','secrets.env','meeting_notes.txt'}.issubset(names))
        self.assertNotEqual(sandbox.agent_root('one'),sandbox.agent_root('two'))
        self.assertTrue(sandbox.agent_root('demo-agent').is_relative_to(sandbox.ROOT))
        self.assertNotIn('.trash',names)
        self.assertIn('fake-demo',self.action('read_file',path='secrets.env').json()['result']['content'])

    def test_nested_write_overwrite_read_and_listing(self):
        self.allow('write_file','read_file','list_files')
        first=self.action('write_file',path='reports/q1.txt',content='hello').json()
        self.assertFalse(first['result']['overwritten'])
        second=self.action('write_file',path='reports/q1.txt',content='updated').json()
        self.assertTrue(second['result']['overwritten'])
        self.assertEqual(self.action('read_file',path='reports/q1.txt').json()['result']['content'],'updated')
        self.assertEqual(self.action('list_files',dir='reports').json()['result']['entries'][0]['path'],'reports/q1.txt')
        self.assertEqual(sandbox.safe_path('demo-agent','reports/q1.txt').read_text(),'updated')

    def test_default_write_is_blocked_and_folder_policy_is_applied(self):
        self.assertEqual(self.action('write_file',path='reports/new.txt',content='draft').json()['status'],'blocked')
        self.assertFalse(sandbox.safe_path('demo-agent','reports/new.txt').exists())
        policy={'id':'default-assistant','name':'scoped','rules':[{'tool':'write_file','action':'allow','when':{'path_prefix':'reports/'}}]}
        self.client.post('/admin/policies',headers=self.admin,json=policy)
        self.assertEqual(self.action('write_file',path='reports/new.txt',content='draft').json()['status'],'executed')
        self.assertEqual(self.action('write_file',path='reports-evil/new.txt',content='draft').json()['status'],'blocked')

    def test_delete_is_recoverable_and_restore_is_admin_only(self):
        self.allow('delete_file','read_file','list_files')
        result=self.action('delete_file',path='report.txt').json()['result']
        self.assertTrue(result['recoverable'])
        self.assertEqual(self.action('read_file',path='report.txt').status_code,404)
        entries=self.action('list_files',dir='.').json()['result']['entries']
        self.assertNotIn('.trash',{e['name'] for e in entries})
        route='/admin/trash/'+result['trash_id']+'/restore'
        self.assertEqual(self.client.post(route,headers=self.agent).status_code,401)
        self.assertEqual(self.client.post(route,headers=self.admin).status_code,200)
        self.assertEqual(self.client.post(route,headers=self.admin).status_code,409)
        self.assertEqual(self.action('read_file',path='report.txt').status_code,200)
        self.assertTrue(self.client.get('/api/verify',headers=self.admin).json()['valid'])

    def test_restore_never_overwrites_a_new_file(self):
        self.allow('delete_file','read_file')
        trash_id=self.action('delete_file',path='report.txt').json()['result']['trash_id']
        sandbox.put_file('demo-agent','report.txt','new work')
        self.assertEqual(self.client.post('/admin/trash/'+trash_id+'/restore',headers=self.admin).status_code,409)
        self.assertEqual(self.action('read_file',path='report.txt').json()['result']['content'],'new work')

    def test_path_traversal_windows_devices_and_trash_are_rejected(self):
        self.allow('read_file','write_file','delete_file','list_files')
        paths=['../outside.txt','/absolute.txt','C:/Windows/system.ini','C:\\Windows\\system.ini','safe/../outside','safe//x','.trash/file','safe/.trash/file','NUL','con.txt','a.txt:stream','safe/file.','safe/%2e%2e/x']
        for value in paths:
            for tool,args in [('read_file',{'path':value}),('write_file',{'path':value,'content':'x'}),('list_files',{'dir':value})]:
                with self.subTest(value=value,tool=tool):
                    self.assertEqual(self.action(tool,**args).status_code,422)
        self.assertEqual(self.action('write_file',path='report.txt/child.txt',content='x').status_code,409)

    def test_link_and_windows_reparse_guards(self):
        for mode,attrs in [(stat.S_IFLNK,0),(stat.S_IFDIR,0x400)]:
            with patch.object(Path,'lstat',return_value=SimpleNamespace(st_mode=mode,st_file_attributes=attrs)):
                with self.assertRaises(HTTPException) as error:
                    sandbox.no_links(Path('irrelevant'))
                self.assertEqual(error.exception.status_code,403)

    def test_real_symlink_cannot_escape(self):
        with tempfile.TemporaryDirectory() as outside:
            marker=Path(outside)/'outside.txt';marker.write_text('private')
            link=sandbox.agent_root('demo-agent')/'escape'
            try:
                link.symlink_to(outside,target_is_directory=True)
            except OSError:
                self.skipTest('Creating symlinks requires privileges on this Windows host; reparse guard is unit tested')
            self.allow('read_file','write_file','list_files','delete_file')
            try:
                self.assertEqual(self.action('read_file',path='escape/outside.txt').status_code,403)
                self.assertEqual(self.action('write_file',path='escape/outside.txt',content='changed').status_code,403)
                self.assertEqual(self.action('list_files',dir='escape').status_code,403)
                self.assertEqual(marker.read_text(),'private')
            finally:
                link.unlink()

    def test_command_never_executes_and_default_policy_blocks_it(self):
        self.assertEqual(self.action('run_command',cmd='whoami').json()['status'],'blocked')
        self.allow('run_command')
        with patch('os.system') as shell,patch('subprocess.run') as process:
            result=self.action('run_command',cmd='echo forbidden > command-marker.txt').json()['result']
            shell.assert_not_called();process.assert_not_called()
        self.assertTrue(result['simulated'])
        self.assertIn('No command was executed',result['stdout'])
        self.assertFalse(sandbox.safe_path('demo-agent','command-marker.txt').exists())

    def test_subject_timestamp_and_secret_detection(self):
        result=self.action('send_email',to='boss@ourcompany.com',subject='Quarterly report',body='ordinary summary').json()['result']
        self.assertEqual(result['subject'],'Quarterly report')
        self.assertIn('T',result['sent_at'])
        message=self.client.get('/api/outbox',headers=self.admin).json()['messages'][0]
        self.assertEqual(message['subject'],'Quarterly report')
        blocked=self.action('send_email',to='boss@ourcompany.com',subject='API_KEY=fake-only',body='ordinary').json()
        self.assertEqual(blocked['detector_rule'],'secret_in_outbound')
        self.assertEqual(len(self.client.get('/api/outbox',headers=self.admin).json()['messages']),1)

    def test_write_and_command_limits_and_subject_validation(self):
        for tool,args in [('write_file',{'path':'large.txt','content':'x'*100001}),('write_file',{'path':'large.txt','content':'界'*40000}),('run_command',{'cmd':''}),('run_command',{'cmd':'x'*1001}),('send_email',{'to':'a@ourcompany.com','subject':'bad\r\nheader','body':'test'})]:
            self.assertEqual(self.action(tool,**args).status_code,422)
        self.assertFalse(sandbox.safe_path('demo-agent','large.txt').exists())

    def test_migration_preserves_files_and_deletion_across_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            env=os.environ.copy();env['AGENTSHIELD_DATA']=directory
            code="import app,sandbox; sandbox.put_file('demo-agent','report.txt','saved work'); c=app.sqlite3.connect(app.DATA/'shield.db'); c.row_factory=app.sqlite3.Row; sandbox.execute(c,'demo-agent',app.Action(tool='delete_file',args={'path':'customers.csv'})); c.commit(); c.close()"
            result=subprocess.run([sys.executable,'-c',code],cwd=str(backend.app.ROOT),env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
            check="import app,sandbox; assert sandbox.safe_path('demo-agent','report.txt').read_text()=='saved work'; assert not sandbox.safe_path('demo-agent','customers.csv').exists()"
            result=subprocess.run([sys.executable,'-c',check],cwd=str(backend.app.ROOT),env=env,capture_output=True,text=True,timeout=20)
            self.assertEqual(result.returncode,0,result.stderr)
    def test_creation_does_not_count_as_destructive_but_overwrites_do(self):
        import detector
        self.allow('write_file','read_file')
        with patch.object(detector,'BURST_LIMIT',1),patch.object(detector,'BURST_WINDOW',3600):
            for i in range(4):
                self.assertEqual(self.action('write_file',path=f'new{i}.txt',content='original').json()['status'],'executed')
            self.assertEqual(self.action('write_file',path='new0.txt',content='updated').json()['status'],'executed')
            self.assertEqual(self.action('write_file',path='new1.txt',content='blocked').json()['detector_rule'],'destructive_burst')
            self.assertEqual(self.action('read_file',path='new1.txt').json()['result']['content'],'original')

    def test_pending_creates_are_reclassified_when_approved_as_overwrites(self):
        import detector
        with backend.app.db() as c:
            c.execute('UPDATE policies SET rules_json=? WHERE id=?',(json.dumps({'name':'review','rules':[{'tool':'write_file','action':'approve'}]}),'default-assistant'))
        with patch.object(detector,'BURST_LIMIT',1),patch.object(detector,'BURST_WINDOW',3600):
            ids=[self.action('write_file',path='review.txt',content=text).json()['id'] for text in ['first','second','third']]
            outcomes=[self.client.post('/api/approvals/'+rid+'/approve',headers=self.admin).json() for rid in ids]
            self.assertEqual([r['status'] for r in outcomes],['executed','executed','blocked'])
            self.assertEqual(outcomes[-1]['detector_rule'],'destructive_burst')
            self.assertEqual(sandbox.safe_path('demo-agent','review.txt').read_text(),'second')

    def test_approval_error_resolves_request_without_repeated_execution(self):
        with backend.app.db() as c:
            c.execute('UPDATE policies SET rules_json=? WHERE id=?',(json.dumps({'name':'review','rules':[{'tool':'read_file','action':'approve'}]}),'default-assistant'))
        pending=self.action('read_file',path='missing.txt').json()['id']
        route='/api/approvals/'+pending+'/approve'
        self.assertEqual(self.client.post(route,headers=self.admin).status_code,404)
        self.assertEqual(self.client.post(route,headers=self.admin).status_code,409)
        self.assertEqual(self.client.get('/api/actions/'+pending,headers=self.agent).json()['status'],'error')
