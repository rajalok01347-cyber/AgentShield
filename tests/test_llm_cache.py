"""Cache contract and record/replay runs against the real local gateway."""
import copy
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import httpx
from agentshield import sandbox
import test_backend as backend
from test_gemini_agent import ScriptedModel, call, ANSWER
from agentshield.gemini_agent import Gemini, AgentError, run_agent, model_outcome, SYSTEM, TOOLS, main
from agentshield.llm_cache import LLMCache, CachedModel, CacheError, request_key, connection


class CacheTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.path=Path(folder.name)/'cache.db'
        self.cache=LLMCache(self.path)

    def wrapper(self,provider,mode,**kwargs):
        return CachedModel(provider,self.cache,mode,'test-model',SYSTEM,copy.deepcopy(TOOLS),report=lambda _:None,**kwargs)

    def test_canonical_keys_and_semantic_changes(self):
        self.assertEqual(request_key({'model':'m','messages':[]}),request_key({'messages':[],'model':'m'}))
        base={'model':'m','messages':['a'],'tools':['read'],'system':'s','generation':{'maxOutputTokens':20}}
        for field,value in [('model','other'),('messages',['b']),('tools',['write']),('system','new'),('generation',{'maxOutputTokens':21})]:
            changed=copy.deepcopy(base);changed[field]=value
            self.assertNotEqual(request_key(base),request_key(changed))

    def test_roundtrip_persists_complete_content_and_metadata(self):
        content=call('read_file',{'path':'report.txt'})
        self.cache.put({'model':'m'},content)
        loaded=LLMCache(self.path).get({'model':'m'})
        self.assertEqual(loaded,content)
        with connection(self.path) as c:
            row=c.execute('SELECT key,request_json,response_json,created_at,response_hash FROM llm_cache').fetchone()
        self.assertEqual(len(row[0]),64);self.assertIn('T',row[3]);self.assertEqual(len(row[4]),64)

    def test_live_bypasses_cache_and_record_always_calls_provider(self):
        provider=ScriptedModel(ANSWER)
        live=self.wrapper(provider,'live')
        with patch.object(self.cache,'get',side_effect=AssertionError('cache read')),patch.object(self.cache,'put',side_effect=AssertionError('cache write')):
            self.assertEqual(live.generate([]),ANSWER)
        provider=ScriptedModel(ANSWER,{'role':'model','parts':[{'text':'updated'}]})
        record=self.wrapper(provider,'record')
        record.generate([]);record.generate([])
        self.assertEqual(len(provider.histories),2)
        self.assertEqual(self.wrapper(None,'replay').generate([])['parts'][0]['text'],'updated')

    def test_replay_never_calls_provider_and_miss_is_an_error(self):
        with self.assertRaisesRegex(CacheError,'Replay cache miss'):
            self.wrapper(None,'replay').generate([])
        record=self.wrapper(ScriptedModel(ANSWER),'record');record.generate([])
        class NoNetwork:
            def generate(self,_): raise AssertionError('Gemini must never be called')
        self.assertEqual(self.wrapper(NoNetwork(),'replay').generate([]),ANSWER)
        with self.assertRaisesRegex(CacheError,'Replay cache miss'):
            self.wrapper(NoNetwork(),'replay').generate([{'role':'user','parts':[{'text':'different task'}]}])

    def test_corrupt_or_invalid_recording_fails_closed(self):
        self.cache.put({'model':'m'},ANSWER)
        with connection(self.path) as c:
            c.execute("UPDATE llm_cache SET response_json='{}'")
        with self.assertRaisesRegex(CacheError,'integrity'):
            self.cache.get({'model':'m'})
        with self.assertRaises(CacheError):
            self.cache.put({'model':'new'},{'role':'model','parts':[{'functionCall':'bad'}]})

    def test_provider_failure_is_not_cached_and_auth_key_is_absent(self):
        with httpx.Client(transport=httpx.MockTransport(lambda _:httpx.Response(429,text='private-test-key'))) as client:
            model=self.wrapper(Gemini(client,'private-test-key'),'record')
            with self.assertRaises(AgentError):model.generate([])
        with connection(self.path) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM llm_cache').fetchone()[0],0)
        self.wrapper(ScriptedModel(ANSWER),'record').generate([])
        with connection(self.path) as c:
            row=c.execute('SELECT request_json,response_json FROM llm_cache').fetchone()
        self.assertNotIn('private-test-key',' '.join(row))

    def test_volatile_metadata_is_removed_without_changing_file_contents(self):
        outcome={'id':'request-1','session_id':'session-1','status':'executed','result':{'content':'id=123; sent_at is part of this file','sent_at':'keep for a read'}}
        read=model_outcome(outcome,'read_file')
        self.assertNotIn('id',read);self.assertNotIn('session_id',read)
        self.assertEqual(read['result'],outcome['result'])
        email=model_outcome({'status':'executed','result':{'message_id':1,'sent_at':'now','body':'literal text'}},'send_email')
        self.assertEqual(email['result'],{'body':'literal text'})


class CacheGatewayTests(unittest.TestCase):
    def setUp(self):
        backend.BackendTests.setUp(self)
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.cache=LLMCache(Path(folder.name)/'cache.db')

    def model(self,provider,mode):
        return CachedModel(provider,self.cache,mode,'test-model',SYSTEM,TOOLS,report=lambda _:None)

    def run_task(self,model,**kwargs):
        return run_agent('Read the demo report.',model,self.client,backend.app.AGENT,report=lambda _:None,**kwargs)

    def test_full_record_replay_twice_uses_fresh_gateway_requests(self):
        provider=ScriptedModel(call('read_file',{'path':'report.txt'}),ANSWER)
        recorded=self.run_task(self.model(provider,'record'))
        replayed=[self.run_task(self.model(None,'replay')) for _ in range(2)]
        self.assertEqual([r['answer'] for r in replayed],[recorded['answer']]*2)
        sessions={r['session_id'] for r in [recorded]+replayed}
        self.assertEqual(len(sessions),3)
        state=self.client.get('/api/state',headers=self.admin).json()
        self.assertEqual(len(state['requests']),3)
        self.assertEqual(len({r['id'] for r in state['requests']}),3)
        self.assertTrue(self.client.get('/api/verify',headers=self.admin).json()['valid'])

    def test_human_approvals_and_outbox_run_again_during_replay(self):
        provider=ScriptedModel(call('send_email',{'to':'partner@example.test','subject':'Demo','body':'summary'}),ANSWER)
        decisions=[]
        def approve(_):
            pending=next(r for r in self.client.get('/api/state',headers=self.admin).json()['requests'] if r['status']=='pending')
            decisions.append(pending['id'])
            self.client.post('/api/approvals/'+pending['id']+'/approve',headers=self.admin)
        self.run_task(self.model(provider,'record'),sleep=approve)
        self.run_task(self.model(None,'replay'),sleep=approve)
        self.assertEqual(len(set(decisions)),2)
        messages=self.client.get('/api/outbox',headers=self.admin).json()['messages']
        self.assertEqual(len(messages),2)
        self.assertNotEqual(messages[0]['id'],messages[1]['id'])

    def test_live_policy_change_changes_next_key_and_causes_miss(self):
        provider=ScriptedModel(call('delete_file',{'path':'report.txt'}),ANSWER)
        self.run_task(self.model(provider,'record'))
        with backend.app.db() as c:
            c.execute('UPDATE policies SET rules_json=? WHERE id=?',(json.dumps({'name':'new','rules':[{'tool':'delete_file','action':'allow'}]}),'default-assistant'))
        with self.assertRaisesRegex(CacheError,'Replay cache miss'):
            self.run_task(self.model(None,'replay'))
        state=self.client.get('/api/state',headers=self.admin).json()
        self.assertEqual(state['requests'][0]['status'],'executed')
        self.assertFalse(sandbox.safe_path('demo-agent','report.txt').exists())
        self.assertEqual(len(self.client.get('/admin/trash',headers=self.admin).json()['files']),1)

    def test_cli_replay_does_not_prompt_for_gemini_key(self):
        from agentshield import gemini_agent
        with patch.dict(os.environ,{'LLM_MODE':'replay','AGENTSHIELD_AGENT_KEY':'test-agent-key'},clear=False),patch('sys.argv',['gemini_agent.py','--cache-db',str(self.cache.path),'unrecorded task']),patch('getpass.getpass',side_effect=AssertionError('No key prompt in replay')),patch.object(gemini_agent.httpx,'Client',return_value=self.client) as clients,patch('builtins.print'):
            self.assertEqual(main(),1)
            self.assertEqual(clients.call_count,1)
        self.assertEqual(self.client.get('/api/state',headers=self.admin).json()['requests'],[])
    def test_recording_both_decision_branches_keeps_separate_followups(self):
        email=call('send_email',{'to':'boss@ourcompany.com','subject':'Demo','body':'summary'})
        def policy(action):
            with backend.app.db() as c:
                c.execute('UPDATE policies SET rules_json=? WHERE id=?',(json.dumps({'name':'branch','rules':[{'tool':'send_email','action':action}]}),'default-assistant'))
        for action in ['allow','block']:
            policy(action)
            self.run_task(self.model(ScriptedModel(copy.deepcopy(email),ANSWER),'record'))
        with connection(self.cache.path) as c:
            self.assertEqual(c.execute('SELECT COUNT(*) FROM llm_cache').fetchone()[0],3)
        for action in ['allow','block']:
            policy(action)
            self.run_task(self.model(None,'replay'))
        self.assertEqual(len(self.client.get('/api/outbox',headers=self.admin).json()['messages']),2)
        requests=self.client.get('/api/state',headers=self.admin).json()['requests']
        self.assertEqual([r['status'] for r in requests],['blocked','executed','blocked','executed'])
