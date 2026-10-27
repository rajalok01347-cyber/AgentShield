"""Offline Gemini contract tests against the real AgentShield API."""
import copy
import unittest
import httpx
import test_backend as backend
from agentshield.gemini_agent import AgentError, Gemini, run_agent


class ScriptedModel:
    def __init__(self, *contents):
        self.contents = list(contents)
        self.histories = []

    def generate(self, history):
        self.histories.append(copy.deepcopy(history))
        return self.contents.pop(0)


def call(name, args, identifier='call-1'):
    return {'role':'model','parts':[{'functionCall':{'name':name,'args':args,'id':identifier},
                                    'thoughtSignature':'opaque-signature'}]}


ANSWER = {'role':'model','parts':[{'text':'Task finished.'}]}


class GeminiTests(unittest.TestCase):
    def setUp(self):
        backend.BackendTests.setUp(self)

    def run_model(self, model, **kwargs):
        return run_agent('test task',model,self.client,backend.app.AGENT,report=lambda _:None,**kwargs)

    def test_read_and_blocked_delete_return_to_model(self):
        first=call('read_file',{'path':'report.txt'})
        model=ScriptedModel(first,call('delete_file',{'path':'report.txt'},'call-2'),ANSWER)
        result=self.run_model(model)
        self.assertEqual(result['tool_calls'],2)
        self.assertEqual(model.histories[1][1],first)
        response=model.histories[1][2]['parts'][0]['functionResponse']
        self.assertEqual(response['id'],'call-1')
        self.assertIn('420,000',response['response']['result']['content'])
        self.assertEqual(model.histories[2][-1]['parts'][0]['functionResponse']['response']['status'],'blocked')

    def test_approval_polls_instead_of_resubmitting(self):
        model=ScriptedModel(call('send_email',{'to':'manager@acme.example','body':'summary'}),ANSWER)
        def approve(_):
            pending=self.client.get('/api/state',headers=self.admin).json()['requests'][0]
            self.client.post('/api/approvals/'+pending['id']+'/approve',headers=self.admin)
        self.run_model(model,sleep=approve)
        self.assertEqual(len(self.client.get('/api/state',headers=self.admin).json()['requests']),1)
        self.assertEqual(len(self.client.get('/api/outbox',headers=self.admin).json()['messages']),1)
        self.assertEqual(model.histories[-1][-1]['parts'][0]['functionResponse']['response']['status'],'executed')

    def test_rejection_is_reported_to_gemini(self):
        model=ScriptedModel(call('send_email',{'to':'manager@acme.example','body':'summary'}),ANSWER)
        def reject(_):
            rid=self.client.get('/api/state',headers=self.admin).json()['requests'][0]['id']
            self.client.post('/api/approvals/'+rid+'/reject',headers=self.admin)
        self.run_model(model,sleep=reject)
        self.assertEqual(model.histories[-1][-1]['parts'][0]['functionResponse']['response']['status'],'rejected')
        self.assertEqual(self.client.get('/api/outbox',headers=self.admin).json()['messages'],[])

    def test_timeout_leaves_request_pending(self):
        ticks=iter([0,2])
        model=ScriptedModel(call('send_email',{'to':'manager@acme.example','body':'summary'}))
        with self.assertRaisesRegex(AgentError,'remains pending'):
            self.run_model(model,approval_timeout=1,clock=lambda:next(ticks))
        self.assertEqual(self.client.get('/api/state',headers=self.admin).json()['requests'][0]['status'],'pending')

    def test_request_status_is_scoped_to_owner(self):
        rid=self.client.post('/api/actions',headers=self.agent,json={'session_id':self.session,'tool':'read_file','args':{'path':'report.txt'}}).json()['id']
        self.assertEqual(self.client.get('/api/actions/'+rid,headers=self.agent).status_code,200)
        self.assertEqual(self.client.get('/api/actions/'+rid,headers=self.admin).status_code,401)
        with backend.app.db() as c:
            c.execute('INSERT OR REPLACE INTO requests(id,agent,tool,args,status,reason,result) VALUES(?,?,?,?,?,?,?)',('foreign','other','read_file','{}','executed','test','null'))
        self.assertEqual(self.client.get('/api/actions/foreign',headers=self.agent).status_code,404)
        self.assertEqual(self.client.get('/api/agent',headers=self.agent).json()['id'],'demo-agent')

    def test_unknown_tool_and_budgets(self):
        model=ScriptedModel(call('run_command',{'command':'anything'}),ANSWER)
        self.run_model(model)
        self.assertEqual(model.histories[-1][-1]['parts'][0]['functionResponse']['response']['status'],'error')
        with self.assertRaisesRegex(AgentError,'Tool-call limit'):
            self.run_model(ScriptedModel(call('read_file',{'path':'report.txt'})),max_tools=0)
        with self.assertRaisesRegex(AgentError,'Model-turn limit'):
            self.run_model(ScriptedModel(call('read_file',{'path':'report.txt'})),max_rounds=1)

    def test_rest_contract_and_error_sanitization(self):
        seen=[]
        def handler(request):
            seen.append(request)
            return httpx.Response(200,json={'candidates':[{'finishReason':'STOP','content':ANSWER}]})
        with httpx.Client(transport=httpx.MockTransport(handler)) as client:
            model=Gemini(client,'private-test-key')
            self.assertEqual(model.generate([{'role':'user','parts':[{'text':'hello'}]}]),ANSWER)
        self.assertEqual(seen[0].headers['x-goog-api-key'],'private-test-key')
        self.assertNotIn('private-test-key',str(seen[0].url))
        for code in [403,429,500]:
            with self.subTest(code=code),httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(code,text='private-test-key'))) as client:
                with self.assertRaises(AgentError) as error:
                    Gemini(client,'private-test-key').generate([])
                self.assertNotIn('private-test-key',str(error.exception))

    def test_parallel_calls_preserve_ids_and_signatures(self):
        batch=call('read_file',{'path':'report.txt'})
        batch['parts'].append({'functionCall':{'name':'delete_file','args':{'path':'report.txt'},'id':'second'}})
        model=ScriptedModel(batch,ANSWER)
        self.run_model(model)
        responses=model.histories[-1][-1]['parts']
        self.assertEqual([r['functionResponse']['id'] for r in responses],['call-1','second'])
        self.assertEqual(model.histories[-1][1],batch)

    def test_incomplete_gemini_response_does_not_execute(self):
        for payload in [{},{'candidates':[{'finishReason':'MAX_TOKENS','content':call('delete_file',{'path':'report.txt'})}]}]:
            with httpx.Client(transport=httpx.MockTransport(lambda r:httpx.Response(200,json=payload))) as client:
                with self.assertRaises(AgentError):
                    Gemini(client,'private-test-key').generate([])
        self.assertEqual(self.client.get('/api/state',headers=self.admin).json()['requests'],[])


if __name__=='__main__':
    unittest.main()
