"""Run with: python -m unittest -v test_backend"""
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

_temp = tempfile.TemporaryDirectory()
os.environ['AGENTSHIELD_DATA'] = _temp.name
os.environ['AGENTSHIELD_AGENT_KEY'] = 'test-agent-key'
os.environ['AGENTSHIELD_ADMIN_KEY'] = 'test-admin-key'
from fastapi.testclient import TestClient
import app


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app.app)
        self.agent = {'x-api-key': 'test-agent-key'}
        self.admin = {'x-admin-key': 'test-admin-key'}
        with app.db() as c:
            for table in ('requests', 'events', 'outbox', 'sessions'):
                c.execute('DELETE FROM '+table)
            c.execute("DELETE FROM files WHERE agent!='demo-agent'")
            c.execute("DELETE FROM agents WHERE id!='demo-agent'")
            c.execute("UPDATE agents SET policy_id='default-assistant' WHERE id='demo-agent'")
            c.execute('UPDATE policies SET rules_json=? WHERE id=?',(app.DEFAULT_POLICY.model_dump_json(),'default-assistant'))
        (app.DATA/'checkpoint.json').unlink(missing_ok=True)
        self.session = self.client.post('/api/sessions',headers=self.agent).json()['id']

    def action(self, tool, **args):
        return self.client.post('/api/actions', headers=self.agent,
                                json={'session_id':self.session,'tool': tool, 'args': args})

    def test_health_and_auth(self):
        self.assertEqual(self.client.get('/health').json(), {'status': 'ok'})
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('text/html', response.headers['content-type'])
        self.assertIn('Connect dashboard', response.text)
        self.assertNotIn(app.ADMIN, response.text)
        self.assertNotIn(app.AGENT, response.text)
        self.assertEqual(self.client.get('/openapi.json').status_code, 200)
        self.assertEqual(self.client.post('/api/actions', json={'tool':'read_file','args':{'path':'report.txt'}}).status_code, 401)
        self.assertEqual(self.client.get('/api/state',headers=self.agent).status_code, 401)

    def test_read_and_missing_file(self):
        response = self.action('read_file', path='report.txt')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()['status'], 'executed')
        self.assertIn('420,000', response.json()['result']['content'])
        self.assertEqual(self.action('read_file', path='missing.txt').status_code,404)

    def test_delete_is_blocked_without_side_effect(self):
        self.assertEqual(self.action('delete_file',path='report.txt').json()['status'],'blocked')
        self.assertEqual(self.action('read_file',path='report.txt').status_code,200)

    def test_email_waits_and_approval_is_single_execution(self):
        response=self.action('send_email',to='manager@acme.example',body='Summary').json()
        self.assertEqual(response['status'],'pending')
        self.assertEqual(self.client.get('/api/outbox',headers=self.admin).json()['messages'],[])
        url='/api/approvals/'+response['id']+'/approve'
        with ThreadPoolExecutor(max_workers=2) as pool:
            codes=list(pool.map(lambda _: self.client.post(url,headers=self.admin).status_code,range(2)))
        self.assertEqual(sorted(codes),[200,409])
        self.assertEqual(len(self.client.get('/api/outbox',headers=self.admin).json()['messages']),1)

    def test_rejection_does_not_send(self):
        rid=self.action('send_email',to='manager@acme.example',body='Summary').json()['id']
        self.assertEqual(self.client.post('/api/approvals/'+rid+'/reject',headers=self.admin).json()['status'],'rejected')
        self.assertEqual(self.client.get('/api/outbox',headers=self.admin).json()['messages'],[])

    def test_invalid_inputs(self):
        for tool,args in [('read_file',{'path':'../secret'}),('read_file',{}),('send_email',{'to':'bad','body':'hello'}),('send_email',{'to':'a@acme.example','body':' '}),('delete_file',{'path':'report.txt','extra':'x'}),('run_command',{})]:
            with self.subTest(tool=tool,args=args):
                self.assertEqual(self.client.post('/api/actions',headers=self.agent,json={'tool':tool,'args':args}).status_code,422)

    def test_tools_are_scoped_to_agent(self):
        with app.db() as c:
            c.execute("INSERT OR REPLACE INTO files VALUES ('other','private.txt','private')")
        self.assertEqual(self.action('read_file',path='private.txt').status_code,404)

    def test_attack_sequence_and_audit_tamper(self):
        self.action('read_file',path='untrusted.txt')
        self.assertEqual(self.action('send_email',to='thief@unknown.example',body='secret').json()['status'],'blocked')
        self.assertTrue(self.client.get('/api/verify',headers=self.admin).json()['valid'])
        self.client.post('/api/demo/tamper',headers=self.admin)
        self.assertFalse(self.client.get('/api/verify',headers=self.admin).json()['valid'])

    def test_off_and_on_demo(self):
        for shield,expected in [(False,'executed'),(True,'blocked')]:
            result=self.client.post('/api/demo',headers=self.admin,json={'shield':shield})
            self.assertEqual(result.status_code,200)
            self.assertEqual(result.json()['steps'][-1]['status'],expected)

    def test_sandbox_delete_implementation(self):
        with app.db() as c:
            c.execute("INSERT INTO files VALUES ('tool-test','disposable.txt','fake')")
            result=app.execute(c,'tool-test',app.Action(tool='delete_file',args={'path':'disposable.txt'}))
            self.assertEqual(result,{'deleted':'disposable.txt'})
            self.assertIsNone(c.execute("SELECT 1 FROM files WHERE agent='tool-test'").fetchone())


if __name__ == '__main__':
    unittest.main()
