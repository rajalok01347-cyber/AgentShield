from contextlib import closing
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pydantic import ValidationError
import test_backend as backend
from agentshield.policy import Conditions, Policy, Rule, evaluate


class PolicyTests(unittest.TestCase):
    def test_first_match_and_default_block(self):
        policy=Policy(name='test',rules=[Rule(tool='delete_file',action='block'),Rule(tool='delete_file',action='allow')])
        self.assertEqual(evaluate(policy,'delete_file',{})[0],'block')
        self.assertEqual(evaluate(policy,'unknown',{})[0],'block')
        self.assertEqual(evaluate(Policy(name='empty',rules=[]),'read_file',{})[0],'block')

    def test_exact_domain_matching(self):
        p=Policy(name='test',rules=[Rule(tool='send_email',action='allow',when=Conditions(to_domain_in=['OurCompany.com'])),Rule(tool='send_email',action='approve')])
        self.assertEqual(evaluate(p,'send_email',{'to':'a@OURCOMPANY.COM'})[0],'allow')
        for to in ['a@evilourcompany.com','a@ourcompany.com.evil','a@sub.ourcompany.com','a@ourcompany.com,b@evil.com','bad']:
            self.assertEqual(evaluate(p,'send_email',{'to':to})[0],'approve')

    def test_path_boundary_and_traversal(self):
        p=Policy(name='test',rules=[Rule(tool='read_file',action='allow',when=Conditions(path_prefix='reports/'))])
        self.assertEqual(evaluate(p,'read_file',{'path':'reports/q1.txt'})[0],'allow')
        for path in ['reports-evil/a.txt','reports/../secrets.env','/reports/a.txt','reports\\a.txt','other/a.txt']:
            self.assertEqual(evaluate(p,'read_file',{'path':path})[0],'block')

    def test_conditions_are_combined_and_size_is_strict(self):
        p=Policy(name='test',rules=[Rule(tool='send_email',action='allow',when=Conditions(to_domain_in=['x.com'],max_size=10))])
        self.assertEqual(evaluate(p,'send_email',{'to':'a@x.com','body':'12'})[0],'allow')
        self.assertEqual(evaluate(p,'send_email',{'to':'a@x.com','body':'123'})[0],'block')
        self.assertEqual(evaluate(p,'send_email',{'to':'a@y.com','body':'1'})[0],'block')

    def test_invalid_conditions_fail_validation(self):
        for condition in [{'to_domain_in':['*.example.com']},{'path_prefix':'../'},{'max_size':0},{'max_size':True},{'unknown':'x'}]:
            with self.subTest(condition=condition),self.assertRaises(ValidationError):
                Conditions.model_validate(condition)


class SessionTests(unittest.TestCase):
    def setUp(self):
        backend.BackendTests.setUp(self)

    def submit(self, sid, tool, **args):
        return self.client.post('/api/actions',headers=self.agent,json={'session_id':sid,'tool':tool,'args':args})

    def test_taint_is_isolated_between_sessions(self):
        clean=self.client.post('/api/sessions',headers=self.agent).json()['id']
        self.submit(self.session,'read_file',path='untrusted.txt')
        self.assertEqual(self.submit(self.session,'send_email',to='x@external.com',body='test').json()['status'],'blocked')
        self.assertEqual(self.submit(clean,'send_email',to='x@external.com',body='test').json()['status'],'pending')
        self.assertEqual(self.client.get('/api/sessions/'+clean,headers=self.agent).json()['tainted'],0)
        self.assertEqual(self.client.get('/api/sessions/'+self.session,headers=self.agent).json()['tainted'],1)

    def test_missing_and_foreign_sessions_are_rejected(self):
        self.assertEqual(self.client.post('/api/actions',headers=self.agent,json={'tool':'read_file','args':{'path':'report.txt'}}).status_code,422)
        with backend.app.db() as c:
            c.execute("INSERT INTO sessions VALUES('foreign','other',0,'now')")
        for sid in ['foreign','missing']:
            self.assertEqual(self.submit(sid,'read_file',path='report.txt').status_code,404)
            self.assertEqual(self.client.get('/api/sessions/'+sid,headers=self.agent).status_code,404)

    def test_bearer_auth_and_default_policy(self):
        headers={'Authorization':'Bearer '+os.environ['AGENTSHIELD_AGENT_KEY']}
        self.assertEqual(self.client.post('/v1/sessions',headers=headers).status_code,200)
        result=self.submit(self.session,'send_email',to='boss@ourcompany.com',body='hello').json()
        self.assertEqual(result['status'],'executed')
        self.assertEqual(len(self.client.get('/api/outbox',headers=self.admin).json()['messages']),1)

    def test_policy_management_and_recheck_before_approval(self):
        rid=self.submit(self.session,'send_email',to='x@external.com',body='test').json()['id']
        policy={'id':'restricted','name':'restricted','rules':[{'tool':'send_email','action':'block','reason':'Policy changed'}]}
        self.assertEqual(self.client.post('/admin/policies',json=policy,headers=self.agent).status_code,401)
        self.assertEqual(self.client.post('/admin/policies',json=policy,headers=self.admin).status_code,200)
        self.assertEqual(self.client.post('/admin/agents/demo-agent/policy',headers=self.admin,json={'policy_id':'restricted'}).status_code,200)
        self.assertEqual(self.client.post('/api/approvals/'+rid+'/approve',headers=self.admin).json()['status'],'blocked')
        self.assertEqual(self.client.get('/api/outbox',headers=self.admin).json()['messages'],[])
        self.assertTrue(self.client.get('/api/verify',headers=self.admin).json()['valid'])

    def test_taint_is_rechecked_for_pending_email(self):
        rid=self.submit(self.session,'send_email',to='x@external.com',body='test').json()['id']
        self.submit(self.session,'read_file',path='untrusted.txt')
        self.assertEqual(self.client.post('/api/approvals/'+rid+'/approve',headers=self.admin).json()['status'],'blocked')
        self.assertEqual(self.client.get('/api/outbox',headers=self.admin).json()['messages'],[])

    def test_invalid_policy_does_not_replace_existing(self):
        before=self.client.get('/admin/policies',headers=self.admin).json()
        bad={'id':'default-assistant','name':'bad','rules':[{'tool':'send_email','action':'allow','when':{'typo':'value'}}]}
        self.assertEqual(self.client.post('/admin/policies',headers=self.admin,json=bad).status_code,422)
        self.assertEqual(self.client.get('/admin/policies',headers=self.admin).json(),before)

    def test_session_id_is_in_audit_and_request(self):
        result=self.submit(self.session,'read_file',path='report.txt').json()
        self.assertEqual(result['session_id'],self.session)
        state=self.client.get('/api/state',headers=self.admin).json()
        payload=json.loads(state['events'][0]['payload'])
        self.assertEqual(payload['session_id'],self.session)
        self.assertEqual(payload['args'],{'path':'report.txt'})
        self.assertEqual(state['requests'][0]['session_id'],self.session)

    def test_old_database_requires_a_clean_data_folder(self):
        with tempfile.TemporaryDirectory() as directory:
            with closing(sqlite3.connect(os.path.join(directory,'shield.db'))) as c:
                c.execute('CREATE TABLE files(agent TEXT,name TEXT,body TEXT)')
                c.commit()
            env=os.environ.copy();env['AGENTSHIELD_DATA']=directory
            result=subprocess.run([sys.executable,'-c','from agentshield import app'],cwd=str(backend.app.ROOT),env=env,capture_output=True,text=True,timeout=20)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('Old database found; delete the data folder and restart',result.stderr)
