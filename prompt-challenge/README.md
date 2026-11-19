# Prompt Challenge — cenários progressivos (v3)

Projeto para **Cloudflare Pages Functions + Neon PostgreSQL + Dify + Groq**. Esta versão foi preparada como atualização do ambiente anterior e **não foi testada com suas credenciais nem com o banco de produção**. Faça backup do Neon antes de executar a migração.

## O que mudou

- Cenários independentes (ex.: RAG 1 iniciante; RAG 2 avançado) criados pelo painel, cada qual com seu conjunto de interfaces Dify principal e fallback.
- Desafios por cenário, com desbloqueio **sequencial**, **livre** ou **por pré-requisitos explícitos**. A conclusão fica persistida em `progress` e tentativas em `attempts`.
- Juiz com prompt e critério armazenados **somente no Neon** (`challenges.judge_prompt`). Requisições ao juiz recebem também o último prompt do participante para detectar eco.
- Limites do juiz parametrizados nas tabelas `challenge_settings` e `scenario_judge_settings`, editáveis no painel; avaliações válidas gravadas atomicamente, enquanto falhas de Groq são **fail closed** e **não contam**.
- Provedores `GROQ_KEY_A` / `GROQ_KEY_B` com fallback em ambos os sentidos, via `judge_providers`, em ordem de prioridade. Se nenhum fornecer um veredito válido, devolve HTTP 503, sem aprovar/reprovar.
- Testes de conexão e funcionais individuais de Dify e juízes na aba **Administração → Diagnóstico de APIs** (sem retornar Secrets). Testes funcionais consomem requisições dos provedores.
- Novo visual neon/cyber, adaptável a celular; renderização do conteúdo do chat via `textContent` e CSP restritiva.
- Tokens de operação efêmeros no Neon impedem duas chamadas concorrentes de chat/julgamento para a mesma missão de gravarem estado simultaneamente. Funções SQL de finalização validam sessão, geração e desafio selecionado.

## Atualização de uma instalação EXISTENTE

1. **Faça snapshot/backup do banco Neon** e mantenha uma cópia do projeto antigo para rollback.
2. Confirme que o banco já recebeu `sql/schema.sql` e `sql/02_multi_interfaces.sql` anteriormente. **Não execute novamente `sample_challenges.sql`**.
3. Execute **apenas** `sql/03_scenarios_and_judge_limits.sql` no SQL Editor do mesmo banco, uma vez. A migração preserva usuários, desafios, progresso e tentativas, associa os desafios atuais ao cenário `oficina-inicial` e atribui os pools A/B ao cenário inicial. A migração encerra transacionalmente com `COMMIT`.
4. Confira:
   ```sql
   SELECT slug, title, active FROM scenarios;
   SELECT c.position,c.title,s.slug FROM challenges c JOIN scenarios s ON s.id=c.scenario_id ORDER BY s.position,c.position;
   SELECT p.label,s.slug FROM scenario_pools sp JOIN interface_pools p ON p.id=sp.pool_id JOIN scenarios s ON s.id=sp.scenario_id;
   SELECT label,secret_name,model,priority,enabled FROM judge_providers ORDER BY priority;
   SELECT * FROM challenge_settings;
   ```
5. Configure no Cloudflare Pages **Production Secrets**: `DATABASE_URL`, `DIFY_KEY_A`, `DIFY_KEY_B`, `GROQ_KEY_A`, `GROQ_KEY_B`, conforme seus pools. Para um novo RAG, crie `DIFY_KEY_C` / `DIFY_KEY_D` como Secrets e cadastre as referências no painel. **Não insira chaves reais no Neon**.
6. Substitua **todo o conteúdo do projeto Pages** com esta pasta `prompt-challenge/` mantendo a raiz correta. Projeto Git com pasta na raiz: `Root directory=/prompt-challenge`, `Build output directory=public`, `Build command=exit 0`.
7. Após o novo deploy, entre como admin. Verifique **Diagnóstico de APIs**, faça o teste de conexão em cada provider e só então testes funcionais. Valide cadastro, login, seleção, troca de desafio, chat, submissão e aprovação.

**Atenção à compatibilidade**: este backend v3 depende da migração `03`. Não publique o novo backend antes de aplicar a migração. Não crie um segundo cenário enquanto o primeiro não estiver validado.

## Instalação limpa

Execute em ordem `sql/schema.sql`, `sql/02_multi_interfaces.sql`, `sql/03_scenarios_and_judge_limits.sql`; configure os Secrets e faça deploy de `public/` + `functions/`. O cadastro inicial do administrador depende de aprovação manual após registro:
```sql
UPDATE users SET role='admin', status='approved' WHERE email='seu@email';
```

## Controle de níveis / novos RAGs

O painel **Cenários** permite criar um nível e definir dependências entre níveis. Em **Interfaces Dify**, associe interfaces novas a esse cenário usando nomes de Secrets (`DIFY_KEY_C`, `DIFY_KEY_D`). Em **Desafios**, escolha o cenário, modo de desbloqueio, dependências e rubrica do juiz. Você pode manter o nível 2 ainda não criado: nenhum recurso adicional é necessário agora.

Os nomes dos Secrets ficam no Neon; seus valores continuam somente no Cloudflare. O fallback Dify por lotação preserva o cenário; uma sessão ativa **não é transferida automaticamente** para outro app no meio de uma conversa.

## Limites e segurança

- `challenge_settings`: limite global de avaliações por janela, tamanho da janela em segundos, e total máximo por desafio (`0` = ilimitado). `scenario_judge_settings` substitui os valores do cenário.
- O juiz armazena um veredito **apenas após resposta válida** do provedor (ou julgamento `exact`). As funções SQL fazem verificação/registro/progresso na mesma transação.
- Um erro de Groq inicia tentativa no segundo juiz. Se ambos falharem, HTTP 503. Não há concessão automática, nem resultado falso registrado.
- Cookies de sessão são `HttpOnly`, `Secure`, `SameSite=Strict`; tokens aleatórios são guardados apenas como hash no banco. POST valida `Origin` e `Content-Type`; todas as rotas administrativas verificam `role=admin` no backend.
- Senhas seguem PBKDF2-SHA256 de 100.000 iterações com salt aleatório, uma solução provisória imposta pelo limite observado no Cloudflare. Considere autenticação gerenciada/Argon2id antes de liberar amplamente.
- SQL de negócio usa parâmetros Neon. Os destinos dos provedores são restritos aos endpoints HTTPS esperados de Groq e Dify; a interface não permite definir destinos de rede arbitrários.
- O frontend usa `textContent` em mensagens não confiáveis, não usa `innerHTML` e tem política CSP básica.

### Limitações que ainda exigem validação antes de uso público

- Testes reais de concorrência/volume, comportamento de quota, expiração de sessões e deploy em Cloudflare/Neon ainda **não foram executados neste ambiente**. Não considere esta revisão uma auditoria de segurança independente.
- Pré-requisitos circulares entre desafios/cenários devem ser evitados; a UI bloqueia autorreferência direta, mas não implementa um detector completo de ciclos indiretos.
- Dados cadastrais requerem consentimento/aviso LGPD, procedimento de exclusão, definição de retenção e backup. Recuperação de senha e confirmação de e-mail ainda não estão incluídas.
- Os dois Secrets Groq podem compartilhar quotas da mesma conta. Fallback de chave não supera limite comum do provedor.
- O modo `blocking` do Dify depende do tipo de app. O teste funcional do Dify envia uma pergunta curta ao aplicativo configurado.
- Mudanças administrativas nos desafios em uma competição em curso podem afetar regras de progressão; planeje versionamento das configurações antes de competições oficiais.

## Versão v4 — histórico, repetição e cronômetro opcional

**Migração obrigatória antes do deploy:** execute `sql/04_replay_history_timers.sql` no Neon (após os arquivos 01–03, que já devem estar aplicados no ambiente v3). Faça um snapshot/backup antes. A migração é incremental: preserva usuários, progresso, mensagens e tentativas. Repetições anteriores à v4 são contabilizadas na primeira execução histórica, não inventadas.

### Recursos

- Vitórias continuam persistidas em `progress.ever_passed`, inclusive durante replays; pré-requisitos usam esta conquista permanente.
- Cada jogada (`challenge_runs`) possui contador de mensagens `user` e histórico recuperável via `/api/review`, mesmo sem vaga ativa no Dify.
- O participante não perde a tela ao vencer: vê feedback, número de prompts e botões de revisão/próxima missão. Se habilitado, pode começar novo replay.
- Administração: `replay_enabled`, `max_replays` (número de repetições **extras**, 0 = nenhuma), `time_limit_minutes` (NULL = sem cronômetro) e `time_limit_policy` (`warn` = aviso, `block` = bloqueio).
- Painel Participantes → **Ver progresso**: mostra desafios vencidos, avaliações e prompts totais por participante.
- A contagem de prompts soma todas as gerações de conversa dentro da mesma jogada. `reset` do Dify não zera esse contador.
- Falha dos juízes continua *fail closed*. Não gera derrota, vitória ou tentativa.

### Exemplos SQL

```sql
-- Permitir até duas novas jogadas depois da primeira vitória
UPDATE challenges SET replay_enabled=true,max_replays=2 WHERE position=1;

-- Avisar após 12 minutos, mas deixar a pessoa continuar
UPDATE challenges SET time_limit_minutes=12,time_limit_policy='warn' WHERE position=1;

-- Sem cronômetro
UPDATE challenges SET time_limit_minutes=NULL WHERE position=1;

-- Opcional: impedir chat/avaliação depois do prazo
UPDATE challenges SET time_limit_minutes=20,time_limit_policy='block' WHERE position=2;

-- Conquistas dos participantes
SELECT u.name,c.title,p.ever_passed,p.run_no,p.completed_at
FROM progress p JOIN users u ON u.id=p.user_id JOIN challenges c ON c.id=p.challenge_id
ORDER BY u.name,c.position;
```

**Teste em homologação:** 1. concluir desafio; 2. conferir feedback sem troca automática; 3. revisar histórico; 4. jogar novamente e conferir que pré-requisitos continuam satisfeitos; 5. contar prompts após reset; 6. conferir limites e relatórios; 7. testar cronômetro com aviso/bloqueio; 8. testar submissões concorrentes e falha dupla do juiz.

Não foi feita validação com sua base Neon ou com Dify/Groq reais. Não implante a migração em produção sem backup e testes.


## Atualização: contestações de julgamento e linguagem inclusiva

**Antes de publicar o código desta versão:** faça backup do Neon e execute `sql/05_appeals_and_progress.sql` no SQL Editor **depois** da migração v4 `04_replay_history_timers.sql`. O ZIP original não incluía os scripts SQL 01–04. Se não foram executados, recupere-os da versão anterior; o script 05 não substitui a estrutura/functions de v4.

- Jogadores podem contestar uma tentativa reprovada, uma vez por tentativa, com justificativa.
- A administração possui a aba **Contestações**, com histórico das mensagens e decisão de aprovar/reprovar.
- Aprovação preserva o veredito original em `attempts`, registra revisão em `judgment_appeals`, marca a conquista permanente em `progress.ever_passed` e encerra a jogada correspondente.
- Reprovação preserva o resultado anterior; a contestação permanece no histórico.
- O acesso via Netlify proxy `cyberactivity.com.br/promptchallenge` foi autorizado na verificação de Origin para POST sem desabilitar essa proteção.
- O script 05 também restaura a coluna `ever_passed` ausente em certas bases, com backfill de vitórias históricas. Se outras colunas/funções v4 estiverem ausentes, execute a migração v4 original antes desta.
- **Limitação de teste:** integração com Neon, Dify, Groq, Netlify e Cloudflare Pages não foi executada neste ambiente; testar em homologação antes da produção.

### Checklist de validação

1. Faça login como jogador aprovado; `/api/state` deve responder 200.
2. Submeta uma avaliação reprovada e envie uma contestação.
3. No painel admin, abra **Contestações**, consulte a conversa e aprove uma contestação.
4. Confirme no SQL Editor `progress.ever_passed = true`, `challenge_runs.won = true`, `judgment_appeals.status = 'approved'`.
5. Confirme que o catálogo libera os pré-requisitos e que o veredito original não foi alterado.
6. Teste reprovação e tentativa de decidir duas vezes (a segunda deve falhar).


## Endpoints privados (Cloudflare Pages)

Configure em **Workers & Pages → Prompt Challenge → Settings → Variables and Secrets** (Production e Preview, conforme o ambiente):

- `DIFY_API_BASE_URL` = `https://api.dify.ai/v1`
- `GROQ_API_BASE_URL` = `https://api.groq.com/openai/v1/chat/completions`

As chaves `DIFY_KEY_A`, `DIFY_KEY_B`, `GROQ_KEY_A` e `GROQ_KEY_B` continuam como Secrets por provedor, conforme a configuração existente.

Os endpoints são validados contra hosts e caminhos permitidos (não é possível cadastrar destinos arbitrários pelo painel). Os valores não são servidos no `index.html` ou no endpoint de configuração do administrador. Variáveis não definidas usam os endereços padrão **apenas no backend** por compatibilidade; para centralizar configuração, defina-as explicitamente.

O HTML do painel é devolvido somente por `GET /api/admin/ui`, após autenticação e autorização de administrador. O bundle JavaScript de interface continua público e não deve conter segredos.

## Correções adicionais desta versão

- `GET /api/state` filtra mensagens pela `generation` atual, para reinícios de conversa realmente esvaziarem a tela.
- `admin/appeals` recebe ID numérico, corrigindo "Dados da decisão inválidos" ao aprovar/reprovar.
- O painel administrativo não é incluído no HTML público; sua marcação é carregada somente por administrador autenticado.


### Revisão humana do julgamento (v4.4)

Após uma avaliação não aprovada, o participante pode clicar em **Solicitar revisão do juiz** e enviar justificativa. A solicitação pode ser reencontrada pelo botão **Revisar avaliações** na tela do desafio ou em **Avaliações e pedidos de revisão** no catálogo, mesmo depois de uma nova conversa. A decisão administrativa é feita na aba **Contestações** (aprovar ou reprovar). Requer a migração `sql/05_appeals_and_progress.sql` já aplicada ao Neon.
