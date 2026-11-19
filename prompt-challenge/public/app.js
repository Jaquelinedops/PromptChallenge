'use strict';
const $=id=>document.getElementById(id);
const ui={me:null,register:false,busy:false,admin:null,state:null,chosenTab:'diagnostics',reviewing:false,activeChallengeId:null,timerEnd:null,timerPolicy:'warn',appealAttemptId:null};
const text=(node,value)=>{node.textContent=String(value??'');return node};
const el=(tag,className='',value='')=>{const n=document.createElement(tag);if(className)n.className=className;if(value!==undefined)text(n,value);return n};
const show=(id,yes)=>{$(id).hidden=!yes};
function notify(message){text($('toast'),message);$('toast').classList.add('show');clearTimeout(notify.timer);notify.timer=setTimeout(()=>$('toast').classList.remove('show'),5000)}
async function api(route,method='GET',body){const response=await fetch('./api/'+route,{method,credentials:'same-origin',headers:body===undefined?{}:{'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body)});const result=await response.json().catch(()=>({error:'Resposta não JSON'}));if(!response.ok)throw Error(result.error||'Falha no servidor');return result}
function setIdentity(){const node=$('identity');node.replaceChildren();if(!ui.me)return;const name=el('span','','Olá, '+ui.me.name+' '),button=el('button','ghost','Sair');button.onclick=async()=>{try{await api('logout','POST',{});location.reload()}catch(e){notify(e.message)}};node.append(name,button)}
function authMode(r){ui.register=r;$('loginTab').classList.toggle('selected',!r);$('registerTab').classList.toggle('selected',r);show('nameField',r);$('name').required=r;$('password').autocomplete=r?'new-password':'current-password';text($('authButton'),r?'Solicitar cadastro':'Entrar')}
$('loginTab').onclick=()=>authMode(false);$('registerTab').onclick=()=>authMode(true);
$('authForm').onsubmit=async event=>{event.preventDefault();const payload={email:$('email').value,password:$('password').value};if(ui.register)payload.name=$('name').value;try{const result=await api(ui.register?'register':'login','POST',payload);if(ui.register){notify(result.message);authMode(false)}else{ui.me=result;await start()}}catch(e){notify(e.message)}};
async function start(){show('auth',false);setIdentity();if(ui.me.role==='admin'){const data=await api('admin/ui');$('admin').innerHTML=data.markup;bindAdmin();show('admin',true)}else show('admin',false);await refresh();if(ui.me.role==='admin')await loadAdmin()}
function bubble(role,content){const n=el('div','bubble '+(role==='user'?'user':''));text(n,content);return n}
function renderCatalogue(challenges){
 const node=$('catalogue');node.replaceChildren();
 for(const c of challenges||[]){
  const item=el('article','mission-item'+(c.passed?' passed':'')+(!c.unlocked?' locked':''));
  item.append(el('div','index',`${c.scenario_title} · #${c.position}`),el('h3','',c.title),el('div','status',c.passed?'✓ Concluído':c.unlocked?'● Disponível':'🔒 Bloqueado'));
  let label,action,enabled;
  if(c.passed){
   if(c.currently_active){label='Continuar desafio';enabled=true;action=async()=>{await api('select','POST',{challenge_id:c.id});await refresh()}}
   else if(c.replay_allowed){label='Fazer novamente';enabled=true;action=()=>replayChallenge(c.id)}
   else {label='Concluído';enabled=false}
  }else{label=c.unlocked?'Selecionar missão':'Pré-requisitos pendentes';enabled=!!c.unlocked;action=async()=>{await api('select','POST',{challenge_id:c.id});await refresh()}}
  const btn=el('button',enabled?'primary':'ghost',label);btn.disabled=!enabled;
  btn.onclick=async()=>{try{if(action)await action()}catch(e){notify(e.message)}};
  item.append(btn);node.append(item);
 }
}
function timerUI(ch){
 ui.timerEnd=ch?.time_limit_minutes&&ch?.run_started_at?Date.parse(ch.run_started_at)+ch.time_limit_minutes*60000:null;
 ui.timerPolicy=ch?.time_limit_policy||'warn'; updateTimer();
}
function updateTimer(){
 const n=$('challengeTimer');if(!n)return;
 if(!ui.timerEnd){n.hidden=true;return}
 n.hidden=false;const seconds=Math.max(0,Math.ceil((ui.timerEnd-Date.now())/1000));
 const mm=String(Math.floor(seconds/60)).padStart(2,'0'),ss=String(seconds%60).padStart(2,'0');
 text(n,seconds===0?(ui.timerPolicy==='block'?'⏱ Tempo encerrado. Novas ações bloqueadas.':'⏱ Tempo sugerido encerrado. Você pode continuar.'):`⏱ Tempo restante: ${mm}:${ss}`);
 n.classList.toggle('expired',seconds===0);
 if(seconds===0&&ui.timerPolicy==='block'){ $('send').disabled=true;$('submit').disabled=true }
}
setInterval(updateTimer,1000);
function setChatLocked(locked){$('query').disabled=locked;$('send').disabled=locked;$('submit').disabled=locked;$('reset').disabled=locked}
function showWinActions(show){$('victoryActions').hidden=!show}
function fillMessages(messages){$('messages').replaceChildren();if(!(messages||[]).length)$('messages').append(el('div','empty','◈ Nenhuma mensagem nesta execução.'));else for(const m of messages)$('messages').append(bubble(m.role,m.content));$('messages').scrollTop=$('messages').scrollHeight}
function renderChallenge(ch){text($('progress'),ch.scenario_title+' · ETAPA '+ch.position+(ch.run_no?' · JOGADA '+ch.run_no:''));text($('challengeTitle'),ch.title);text($('description'),ch.description);text($('hint'),ch.hint);ui.activeChallengeId=ch.id;timerUI(ch)}
async function openReview(challengeId,runNo=0){
 const r=await api('review?challenge_id='+encodeURIComponent(challengeId)+(runNo?'&run_no='+runNo:''));
 ui.reviewing=true;ui.activeChallengeId=challengeId;show('chooser',false);show('activity',false);show('game',true);
 renderChallenge({...r.challenge,run_no:r.run_no,run_started_at:null,time_limit_minutes:null});fillMessages(r.messages);
 const run=r.runs.find(x=>x.run_no===r.run_no);text($('promptCounter'),'Prompts enviados nesta jogada: '+(run?.prompt_count||0));
 text($('sessionInfo'),'Histórico salvo · jogada '+r.run_no);
 const history=$('reviewHistory');history.hidden=false;history.replaceChildren();for(const runItem of r.runs){const b=el('button','ghost',`Jogada ${runItem.run_no} · ${runItem.prompt_count} prompts${runItem.won?' · ✓':''}`);b.disabled=runItem.run_no===r.run_no;b.onclick=()=>openReview(challengeId,runItem.run_no).catch(e=>notify(e.message));history.append(b)}
 const last=r.attempts.at(-1);const won=!!run?.won;
 $('result').className=won?'status-good':'status-bad';text($('result'),won?'✓ Desafio concluído. Resultado preservado no Neon.':last?`Último julgamento: ${last.result?'Aprovado':'Não aprovado'}`:'Histórico de execução');
 setChatLocked(true);showWinActions(won);
 // A revisão só pode ser solicitada diretamente sob o resultado do juiz na sessão ativa.
 show('appealBox',false);
}
async function replayChallenge(challengeId){
 if(!confirm('Tentar novamente este desafio? A vitória anterior será preservada.'))return;
 try{await api('replay','POST',{challenge_id:challengeId});ui.reviewing=false;await refresh();notify('Nova tentativa iniciada. A vitória anterior foi preservada.')}catch(e){notify(e.message)}
}
async function refresh(){try{const state=await api('state');ui.state=state;renderCatalogue(state.catalogue);
 if(state.reviewRequired){await openReview(state.challenge.id);return}
 ui.reviewing=false;$('reviewHistory').hidden=true;showWinActions(false);show('appealBox',false);
 if(state.selectionRequired){show('chooser',true);show('activity',false);show('game',false);return}
 if(state.sessionRequired){show('chooser',false);show('activity',true);show('game',false);text($('activityStatus'),'Missão: '+state.challenge?.title+'. Clique para ocupar uma vaga disponível.');return}
 show('chooser',false);show('activity',false);show('game',true);
 renderChallenge(state.challenge);text($('sessionInfo'),'Assistente RAG · até '+new Date(state.expires_at).toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}));
 fillMessages(state.messages);text($('promptCounter'),'Prompts enviados nesta jogada: '+(state.prompt_count||0));
 text($('result'),'');$('result').className='';setChatLocked(false);updateTimer();
    const last=state.lastJudgment;
    if(last){$('result').className=last.result?'status-good':'status-bad';text($('result'),last.result?'✓ Desafio concluído.':'Último julgamento: não aprovado.')}
    configureAppeal(last?.result?null:last?.id,state.appeals||[]);
 }catch(e){notify(e.message)}}
async function choose(){show('chooser',true);show('activity',false);show('game',false);try{const {challenges}=await api('catalogue');if(ui.state)ui.state.catalogue=challenges;renderCatalogue(challenges)}catch(e){notify(e.message);renderCatalogue(ui.state?.catalogue||[])}}
$('changeChallenge').onclick=choose;$('returnChooser').onclick=choose;
$('activate').onclick=async()=>{try{$('activate').disabled=true;const r=await api('activate','POST',{});notify('Sessão iniciada. Boa sorte!');await refresh()}catch(e){notify(e.message)}finally{$('activate').disabled=false}};
$('chatForm').onsubmit=async event=>{event.preventDefault();if(ui.busy)return;const query=$('query').value.trim();if(!query)return;ui.busy=true;$('send').disabled=true;const messages=$('messages');messages.querySelector('.empty')?.remove();messages.append(bubble('user',query));$('query').value='';const loading=bubble('assistant','Consultando o assistente...');messages.append(loading);messages.scrollTop=messages.scrollHeight;try{const result=await api('chat','POST',{text:query});if(result.reset){notify(result.message);await refresh()}else {text(loading,result.answer||'(Resposta vazia)');if(result.prompt_count!==undefined)text($('promptCounter'),'Prompts enviados nesta jogada: '+result.prompt_count)}}catch(e){notify(e.message);await refresh()}finally{ui.busy=false;$('send').disabled=false}};
$('submit').onclick=async()=>{if(ui.busy)return;ui.busy=true;$('submit').disabled=true;try{const r=await api('submit','POST',{});$('result').className=r.won?'status-good':'status-bad';text($('result'),r.won?'✓ Desafio vencido.':'✕ Ainda não.');if(r.prompt_count!==undefined)text($('promptCounter'),'Prompts enviados nesta jogada: '+r.prompt_count);configureAppeal(r.won?null:r.attempt_id,[]);if(r.won){notify('Conquista registrada! A conversa permanece disponível.');setChatLocked(true);showWinActions(true)}}catch(e){notify(e.message)}finally{ui.busy=false;$('submit').disabled=false}};
function configureAppeal(attemptId,appeals=[]){
 ui.appealAttemptId=attemptId||null;
 const box=$('appealBox'),form=$('appealForm'),status=$('appealStatus');
 const existing=(appeals||[]).find(x=>String(x.attempt_id)===String(attemptId))||(appeals||[]).find(x=>x.status==='pending'||x.status==='approved'||x.status==='rejected');
 box.hidden=!attemptId&&!existing;
 form.hidden=!attemptId||!!existing;
 text(status,existing?existing.status==='pending'?'Revisão solicitada. Aguardando decisão da administração.':existing.status==='approved'?'Revisão aprovada pela administração.':'Revisão reprovada pela administração. '+(existing.admin_note||''):'');
}
$('appealForm').onsubmit=async e=>{e.preventDefault();if(!ui.appealAttemptId)return;const button=e.currentTarget.querySelector('button[type=submit]');button.disabled=true;try{await api('appeals','POST',{attempt_id:String(ui.appealAttemptId),reason:$('appealReason').value.trim()});notify('Pedido de revisão encaminhado à administração.');configureAppeal(ui.appealAttemptId,[{attempt_id:ui.appealAttemptId,status:'pending'}])}catch(err){notify(err.message)}finally{button.disabled=false}};
$('nextMission').onclick=()=>{ui.reviewing=false;choose()};
$('reset').onclick=async()=>{if(ui.busy||!confirm('Limpar o chat e iniciar uma nova conversa com o assistente? O histórico anterior ficará salvo no sistema.'))return;ui.busy=true;$('reset').disabled=true;try{await api('reset','POST',{});fillMessages([]);text($('result'),'');$('result').className='';show('appealBox',false);$('query').value='';await refresh();notify('Chat limpo. A próxima mensagem iniciará uma nova conversa.')}catch(e){notify(e.message)}finally{ui.busy=false;$('reset').disabled=false}};
function option(select,id,label){const o=el('option','',label);o.value=id;select.append(o)}
function fillSelect(id,items,placeholder=false){const target=$(id);target.replaceChildren();if(placeholder)option(target,'','Todos os cenários (padrão)');for(const item of items)option(target,item.id,item.title)}
function getSelected(id){return [...$(id).selectedOptions].map(x=>x.value).filter(Boolean)}
function setSelected(id,items){for(const o of $(id).options)o.selected=items.includes(o.value)}
function getChallengePrerequisites(){return [...document.querySelectorAll('#challengeDependencies input[type="checkbox"]:checked')].map(x=>x.value)}
function setChallengePrerequisites(ids){const wanted=new Set(ids);for(const input of document.querySelectorAll('#challengeDependencies input[type="checkbox"]'))input.checked=wanted.has(input.value);updatePrerequisiteUI()}
function populateChallengePrerequisites(challenges){const target=$('challengeDependencies');const previous=new Set(getChallengePrerequisites());target.replaceChildren();for(const challenge of challenges){const label=el('label','prereq-choice');const box=document.createElement('input');box.type='checkbox';box.value=challenge.id;box.checked=previous.has(challenge.id);box.onchange=updatePrerequisiteUI;label.append(box,el('span','',`#${challenge.position} · ${challenge.title}`));target.append(label)}updatePrerequisiteUI()}
function updatePrerequisiteUI(){const enabled=$('unlockMode').value==='prerequisites';const current=$('editId').value;let count=0;for(const label of $('challengeDependencies').querySelectorAll('.prereq-choice')){const box=label.querySelector('input');const self=!!current&&box.value===current;box.disabled=!enabled||self;label.classList.toggle('prereq-disabled',!enabled||self);if(self)box.checked=false;if(box.checked)count++}text($('prereqCount'),count===0?'Nenhum selecionado':`${count} selecionado(s)`);text($('prereqHelp'),enabled?'Marque um ou mais desafios que devem ser concluídos antes de liberar este.':$('unlockMode').value==='sequential'?'Sequencial: a ordem dos desafios determina o desbloqueio. Para escolher dependências, altere para “Por pré-requisitos”.':'Livre: o desafio não exige conclusão de outros desafios.');$('clearPrerequisites').disabled=!enabled}

function fieldMap(pairs,source){for(const [id,key] of pairs)$(id).value=source[key]??''}
function rowLine(title,subtitle,callback){const row=el('div','entry'),desc=el('div');desc.append(el('b','',title),el('br'),el('small','',subtitle));row.append(desc);if(callback){const btn=el('button','ghost','Editar');btn.onclick=callback;row.append(btn)}return row}
function setTab(name){ui.chosenTab=name;for(const b of document.querySelectorAll('#adminTabs button'))b.classList.toggle('selected',b.dataset.tab===name);for(const panel of document.querySelectorAll('.admin-panel'))panel.hidden=panel.id!=='panel-'+name}
function diagnosticCard(kind,provider){const card=el('div','diagnostic-card');card.append(el('div','eyebrow',kind==='dify'?'ASSISTENTE RAG':'AVALIADOR'),el('h3','',provider.label),el('div','diagnostic-meta',kind==='dify'?`${provider.dify_secret_name} · ${provider.max_active} vagas`:provider.secret_name+' · '+provider.model));const status=el('div','diagnostic-output','Ainda não testada.');const actions=el('div','diagnostic-actions');for(const [mode,label] of [['connect','Testar conexão'],['functional','Teste funcional']]){const button=el('button',mode==='functional'?'ghost':'primary',label);button.onclick=async()=>{button.disabled=true;status.className='diagnostic-output';text(status,'Verificando '+provider.label+'...');try{const r=await api('admin/diagnostics','POST',{kind,id:provider.id,mode});status.className='diagnostic-output '+(r.ok?'good':'bad');text(status,`${r.ok?'✓ Disponível':'✕ Indisponível'} · HTTP ${r.status??'—'} · ${r.latency_ms} ms\n${r.note}`)}catch(e){status.className='diagnostic-output bad';text(status,e.message)}finally{button.disabled=false}};actions.append(button)}card.append(actions,status);return card}
function renderDiagnostics(){const root=$('diagnostics');root.replaceChildren();for(const iface of ui.admin.interfaces)root.append(diagnosticCard('dify',iface));for(const prov of ui.admin.providers)root.append(diagnosticCard('judge',prov))}
async function loadAdmin(){try{const [u,c,i,s,j,ap]=await Promise.all(['admin/users','admin/challenges','admin/interfaces','admin/scenarios','admin/judge-settings','admin/appeals'].map(x=>api(x)));ui.admin={users:u.users,challenges:c.challenges,prerequisites:c.prerequisites,interfaces:i.interfaces,scenarios:s.scenarios,scenarioDeps:s.dependencies,providers:j.providers,settings:j.settings[0],overrides:j.overrides,appeals:ap.appeals};renderAdmin()}catch(e){notify('Falha ao carregar painel: '+e.message)}}
async function loadVictories(page=0){
 const root=$('victoriesList');if(!root)return;
 root.replaceChildren(el('p','muted','Carregando conversas vencedoras...'));
 try{
  const data=await api('admin/victories?page='+page);
  ui.victoriesPage=data.page;
  root.replaceChildren();
  if(!data.victories.length)root.append(el('p','muted',page?'Não existem mais vitórias nesta página.':'Nenhuma conversa vencedora registrada.'));
  for(const win of data.victories){
   const card=el('div','entry victory-entry');
   const details=el('div','victory-details');
   const source=win.source==='admin'?'Aprovada pelo administrador (reavaliação)':'Aprovada pelo juiz';
   details.append(el('b','',win.player_name+' · '+win.challenge_title),
    el('div','muted',win.scenario_title+' · Jogada '+win.run_no+' · '+win.prompt_count+' prompts'),
    el('div','muted',source+' · '+(win.approved_at?new Date(win.approved_at).toLocaleString('pt-BR'):'Data indisponível')));
   const open=el('button','ghost','Ver conversa completa');
   open.onclick=async()=>{
    open.disabled=true;
    try{
     const review=await api('review?challenge_id='+encodeURIComponent(win.challenge_id)+'&run_no='+win.run_no+'&user_id='+encodeURIComponent(win.user_id));
     const existing=card.querySelector('.victory-conversation');if(existing){existing.remove();return}
     const history=el('div','victory-conversation');
     history.append(el('h3','','Histórico da jogada '+win.run_no));
     for(const m of review.messages)history.append(bubble(m.role,m.content));
     if(!review.messages.length)history.append(el('p','muted','Nenhuma mensagem registrada para esta jogada.'));
     history.append(el('p','muted','Origem da vitória: '+source));
     if(win.verdict)history.append(el('p','muted','Parecer do juiz: '+win.verdict));
     if(win.admin_note)history.append(el('p','muted','Observação do administrador: '+win.admin_note));
     const close=el('button','ghost','Fechar conversa');close.onclick=()=>history.remove();history.append(close);
     card.append(history);
    }catch(err){notify(err.message)}finally{open.disabled=false}
   };
   card.append(details,open);root.append(card);
  }
  $('victoriesPrevious').disabled=page===0;
  $('victoriesNext').disabled=!data.has_more;
  text($('victoriesPage'),'Página '+(page+1));
 }catch(err){root.replaceChildren(el('p','status-bad','Falha ao carregar vitórias: '+err.message));notify(err.message)}
}
function renderAppeals(){const root=$('appealsList');root.replaceChildren();const pending=ui.admin?.appeals||[];
 if(!pending.length){root.append(el('p','muted','Nenhuma contestação pendente.'));return}
 for(const ap of pending){const card=el('div','appeal-review entry');const details=el('div');details.append(el('b','',ap.player_name+' · '+ap.challenge_title),el('p','muted','Veredicto do juiz: '+(ap.judge_feedback||'Sem justificativa')),el('p','','Contestação: '+ap.reason));card.append(details);
 const actions=el('div','appeal-actions');const see=el('button','ghost','Ver conversa');see.onclick=async()=>{try{const review=await api('review?challenge_id='+encodeURIComponent(ap.challenge_id)+'&run_no='+ap.run_no+'&user_id='+encodeURIComponent(ap.user_id));const popup=$('appealConversation');if(popup)popup.remove();const modal=el('div','appeal-conversation');modal.id='appealConversation';modal.append(el('h3','','Histórico da conversa · '+ap.player_name));for(const m of review.messages)modal.append(el('p','', (m.role==='user'?'Participante: ':'Assistente: ')+m.content));const close=el('button','ghost','Fechar histórico');close.onclick=()=>modal.remove();modal.prepend(close);card.append(modal)}catch(err){notify(err.message)}};actions.append(see);
 for(const [decision,label] of [['approved','Aprovar'],['rejected','Reprovar']]){const b=el('button',decision==='approved'?'primary':'ghost',label);b.onclick=async()=>{const note=prompt('Observações da revisão (opcional):','');if(note===null)return;try{await api('admin/appeals','POST',{id:Number(ap.id),decision,note});notify('Contestação '+(decision==='approved'?'aprovada':'reprovada'));await loadAdmin()}catch(err){notify(err.message)}};actions.append(b)}card.append(actions);root.append(card)}
}
function renderAdmin(){const d=ui.admin;renderDiagnostics();renderAppeals();const users=$('users');users.replaceChildren();for(const u of d.users){const row=rowLine(u.name+' · '+u.email,u.role+' / '+u.status);const controls=el('div');for(const [status,label] of [['approved','Aprovar'],['rejected','Rejeitar'],['pending','Pendente']]){const b=el('button','ghost',label);b.disabled=u.status===status;b.onclick=async()=>{try{await api('admin/users','POST',{id:u.id,status});await loadAdmin()}catch(e){notify(e.message)}};controls.append(b)}const inspect=el('button','ghost','Ver progresso');inspect.onclick=()=>showStudentProgress(u.id);controls.append(inspect);row.append(controls);users.append(row)}
async function showStudentProgress(id){try{const data=await api('admin/progress?user_id='+encodeURIComponent(id));const panel=$('studentProgress');panel.replaceChildren();panel.hidden=false;panel.append(el('h3','',data.participant.name+' · '+data.participant.email),el('p','muted','Total de prompts registrados: '+data.totals.total_prompts));if(!data.progress.length)panel.append(el('p','muted','Nenhum desafio iniciado.'));for(const p of data.progress){const item=el('div','entry');const info=el('div');info.append(el('b','',p.scenario_title+' · '+p.title),el('div','muted',`${p.ever_passed?'✓ Concluído':'Em andamento'} · ${p.total_prompts} prompts · ${p.evaluations} avaliações · ${p.run_no} jogada(s)`));item.append(info);panel.append(item)}panel.scrollIntoView({behavior:'smooth',block:'nearest'})}catch(e){notify(e.message)}}
const scenarios=$('scenarios');scenarios.replaceChildren();for(const s of d.scenarios)scenarios.append(rowLine(s.title,`${s.slug} · nível ${s.position} · ${s.active?'ativo':'inativo'}`,()=>{fieldMap([['scenarioId','id'],['scenarioSlug','slug'],['scenarioTitle','title'],['scenarioDescription','description'],['scenarioPosition','position']],s);$('scenarioActive').checked=s.active;setSelected('scenarioDependencies',d.scenarioDeps.filter(x=>x.scenario_id===s.id).map(x=>x.prerequisite_scenario_id));$('scenarioForm').scrollIntoView({behavior:'smooth'})}));
for(const id of ['poolScenario','challengeScenario','scenarioDependencies'])fillSelect(id,d.scenarios);
fillSelect('limitsScenario',d.scenarios,true);
const pools=$('interfaces');pools.replaceChildren();for(const p of d.interfaces)pools.append(rowLine(p.label,`${p.active_sessions}/${p.max_active} vagas · ${p.duration_minutes} min · ${p.dify_secret_name} · ${p.enabled?'ativo':'inativo'}`,()=>{fieldMap([['poolId','id'],['poolLabel','label'],['poolPriority','priority'],['poolCapacity','max_active'],['poolDuration','duration_minutes'],['poolIdle','idle_minutes'],['poolDifySecret','dify_secret_name'],['poolScenario','scenario_id']],p);$('poolEnabled').checked=p.enabled;$('interfaceForm').scrollIntoView({behavior:'smooth'})}));
const pro=$('providers');pro.replaceChildren();for(const p of d.providers)pro.append(rowLine(p.label,`${p.secret_name} · ${p.model} · prioridade ${p.priority}`,()=>{fieldMap([['providerId','id'],['providerLabel','label'],['providerSecret','secret_name'],['providerModel','model'],['providerPriority','priority']],p);$('providerEnabled').checked=p.enabled;$('providerForm').scrollIntoView({behavior:'smooth'})}));
const cs=$('challenges');cs.replaceChildren();for(const c of d.challenges)cs.append(rowLine('#'+c.position+' · '+c.title,`${d.scenarios.find(s=>s.id===c.scenario_id)?.title||'Cenário'} · ${c.judge_mode} · ${c.unlock_mode}`,()=>{fieldMap([['editId','id'],['challengeScenario','scenario_id'],['unlockMode','unlock_mode'],['position','position'],['title','title'],['challengeDescription','description'],['challengeHint','hint'],['judgeMode','judge_mode'],['expected','expected_answer'],['judgePrompt','judge_prompt']],c);$('active').checked=c.active;$('replayEnabled').checked=!!c.replay_enabled;$('maxReplays').value=c.max_replays??0;$('timeLimit').value=c.time_limit_minutes??'';$('timePolicy').value=c.time_limit_policy||'warn';setChallengeFormMode(c);setChallengePrerequisites(d.prerequisites.filter(p=>p.challenge_id===c.id).map(p=>p.prerequisite_id));$('challengeForm').scrollIntoView({behavior:'smooth'})}));
populateChallengePrerequisites(d.challenges);
if(!ui.limitEdited){$('judgeRate').value=d.settings.judge_rate_limit;$('judgeWindow').value=d.settings.judge_window_seconds;$('judgeMax').value=d.settings.judge_max_per_challenge}
}
function formJSON(form){const o={};for(const field of form.querySelectorAll('input,textarea,select')){if(!field.id||field.type==='submit')continue;o[field.id]=field.type==='checkbox'?field.checked:field.value}return o}
async function save(route,payload,form){try{await api(route,'POST',payload);notify(route==='admin/challenges'?(payload.id?'Desafio atualizado':'Novo desafio criado'):'Alterações salvas');if(route==='admin/challenges')clearChallengeForm();else{form.reset();for(const hidden of form.querySelectorAll('input[type=hidden]'))hidden.value=''}await loadAdmin()}catch(e){notify(e.message)}}
function setChallengeFormMode(challenge=null){
 const isEditing=!!challenge?.id;
 $('editId').value=isEditing?challenge.id:'';
 text($('challengeEditHeading'),isEditing?'Editando: '+challenge.title:'Novo desafio');
 text($('challengeModeNotice'),isEditing?'Modo edição — alterações serão aplicadas somente a este desafio.':'Modo criação — um novo desafio será inserido; os anteriores serão preservados.');
 text($('saveChallengeButton'),isEditing?'Atualizar desafio':'Criar desafio');
}
function clearChallengeForm(){
 const form=$('challengeForm');form.reset();
 $('editId').value='';
 setChallengePrerequisites([]);
 $('replayEnabled').checked=false;$('maxReplays').value='0';$('timeLimit').value='';$('timePolicy').value='warn';$('active').checked=true;
 setChallengeFormMode(null);updatePrerequisiteUI();
}
function bindAdmin(){
$('unlockMode').onchange=updatePrerequisiteUI;
$('clearPrerequisites').onclick=()=>setChallengePrerequisites([]);
for(const b of document.querySelectorAll('#adminTabs button'))b.onclick=()=>{setTab(b.dataset.tab);if(b.dataset.tab==='victories')loadVictories(0)};
$('reloadDiagnostics').onclick=async()=>{await loadAdmin();setTab('diagnostics')};
$('refreshAppeals').onclick=loadAdmin;
$('refreshVictories').onclick=()=>loadVictories(0);
$('victoriesPrevious').onclick=()=>loadVictories(Math.max(0,(ui.victoriesPage||0)-1));
$('victoriesNext').onclick=()=>loadVictories((ui.victoriesPage||0)+1);
$('scenarioForm').onsubmit=e=>{e.preventDefault();save('admin/scenarios',{id:$('scenarioId').value||undefined,slug:$('scenarioSlug').value,title:$('scenarioTitle').value,description:$('scenarioDescription').value,position:Number($('scenarioPosition').value),active:$('scenarioActive').checked,prerequisite_ids:getSelected('scenarioDependencies')},e.currentTarget)};
$('interfaceForm').onsubmit=e=>{e.preventDefault();save('admin/interfaces',{id:$('poolId').value||undefined,scenario_id:$('poolScenario').value,label:$('poolLabel').value,priority:Number($('poolPriority').value),max_active:Number($('poolCapacity').value),duration_minutes:Number($('poolDuration').value),idle_minutes:Number($('poolIdle').value),enabled:$('poolEnabled').checked,dify_base_url:$('poolDifyUrl').value,dify_secret_name:$('poolDifySecret').value},e.currentTarget)};
$('providerForm').onsubmit=e=>{e.preventDefault();save('admin/judge-providers',{id:$('providerId').value||undefined,label:$('providerLabel').value,secret_name:$('providerSecret').value,endpoint:$('providerUrl').value,model:$('providerModel').value,priority:Number($('providerPriority').value),enabled:$('providerEnabled').checked},e.currentTarget)};
$('newChallenge').onclick=()=>{clearChallengeForm();$('challengeForm').scrollIntoView({behavior:'smooth',block:'start'});$('title').focus()};
$('challengeForm').onsubmit=e=>{e.preventDefault();save('admin/challenges',{id:$('editId').value||undefined,scenario_id:$('challengeScenario').value,position:Number($('position').value),title:$('title').value,description:$('challengeDescription').value,hint:$('challengeHint').value,judge_mode:$('judgeMode').value,expected_answer:$('expected').value,judge_prompt:$('judgePrompt').value,unlock_mode:$('unlockMode').value,prerequisite_ids:$('unlockMode').value==='prerequisites'?getChallengePrerequisites():[],active:$('active').checked,replay_enabled:$('replayEnabled').checked,max_replays:Number($('maxReplays').value),time_limit_minutes:$('timeLimit').value===''?null:Number($('timeLimit').value),time_limit_policy:$('timePolicy').value},e.currentTarget)};
$('limitsScenario').onchange=()=>{const a=ui.admin;const override=a.overrides.find(x=>x.scenario_id===$('limitsScenario').value)||a.settings;$('judgeRate').value=override.judge_rate_limit;$('judgeWindow').value=override.judge_window_seconds;$('judgeMax').value=override.judge_max_per_challenge};
$('limitsForm').onsubmit=e=>{e.preventDefault();save('admin/judge-settings',{scenario_id:$('limitsScenario').value||null,judge_rate_limit:Number($('judgeRate').value),judge_window_seconds:Number($('judgeWindow').value),judge_max_per_challenge:Number($('judgeMax').value)},e.currentTarget)};
}
(async()=>{try{ui.me=await api('me');await start()}catch{show('auth',true);show('chooser',false);show('activity',false);show('game',false);show('admin',false)}})();
