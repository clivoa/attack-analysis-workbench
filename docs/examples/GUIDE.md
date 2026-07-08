# 📚 Guia Completo: Exemplos de Planos e Exports do Workbench

Bem-vindo! Este diretório contém **exemplos práticos e documentação completa** de como usar o Attack Analysis Workbench para gerar planos, relatórios e backlog de detecção em diferentes cenários.

---

## 🎯 Por Onde Começar?

### 1️⃣ Novo no Workbench?
👉 **Leia primeiro:** [README.md](./README.md)
- Visão geral da plataforma
- Estrutura de dados
- Três personas principais (CTI, Detection Engineer, SOC Lead)
- Fluxo de trabalho completo

### 2️⃣ Quer Entender Como Usar?
👉 **Leia:** [shared/how-to-use-exports.md](./shared/how-to-use-exports.md)
- Guia prático passo-a-passo
- Diferentes formatos de export (JSON, Markdown, Navigator Layer)
- Padrões de workflow
- Troubleshooting

### 3️⃣ Precisa de Referência Técnica?
👉 **Leia:** [shared/data-model-reference.md](./shared/data-model-reference.md)
- Estrutura completa dos dados
- Campos e tipos
- Exemplos JSON
- Queries SQL

---

## 📂 Estrutura dos Exemplos

```
examples/
├── 📄 README.md
│   └─ Visão geral + casos de uso
│
├── cti-analyst/
│   ├── 📋 threat-actor-profile.md
│   │   └─ Exemplo: Perfil de ameaça (APT29 + Lazarus)
│   │      Com técnicas, overlap, análise de risco
│   │
│   └── 🔗 navigator-layer-guide.md
│       └─ Como exportar e compartilhar layers
│           com MITRE ATT&CK Navigator
│
├── detection-engineer/
│   ├── 📊 windows-detection-backlog.md
│   │   └─ Exemplo: Backlog de detecção Windows
│   │      Com priorização, regras, KPIs
│   │
│   ├── 📊 linux-detection-backlog.md
│   │   └─ (Será adicionado)
│   │
│   └── 📖 using-detection-cards.md
│       └─ (Será adicionado)
│
├── soc-lead/
│   ├── 📈 monthly-coverage-report.md
│   │   └─ Exemplo: Relatório mensal de cobertura
│   │      Com KPIs, blind spots, ROI
│   │
│   ├── 🔍 blind-spots-analysis.md
│   │   └─ (Será adicionado)
│   │
│   └── 💰 mitigation-roi-planning.md
│       └─ (Será adicionado)
│
└── shared/
    ├── 📖 how-to-use-exports.md
    │   └─ Guia prático: como exportar e usar
    │
    └── 📚 data-model-reference.md
        └─ Especificação técnica dos dados
```

---

## 👥 Por Persona

### 🔴 CTI Analyst (Analista de Inteligência)

**Objetivo:** Documentar adversários e suas TTPs (Tactics, Techniques, Procedures)

**Arquivos Relevantes:**
1. [cti-analyst/threat-actor-profile.md](./cti-analyst/threat-actor-profile.md) ⭐
   - **O quê:** Exemplo completo de perfil de ator de ameaça
   - **Como usar:** Copie a estrutura para seus atores
   - **Conteúdo:**
     - Perfil individual de cada ator
     - Análise de overlap (técnicas compartilhadas)
     - Divergências estratégicas
     - Recomendações para detecção

2. [cti-analyst/navigator-layer-guide.md](./cti-analyst/navigator-layer-guide.md) ⭐
   - **O quê:** Como exportar e compartilhar profiles
   - **Como usar:** Passo-a-passo para criar Navigator layers
   - **Conteúdo:**
     - Export do Workbench em JSON
     - Uso no Navigator (web tool)
     - Colaboração em equipe
     - Integração com git

**Workflow Típico:**
```
Dia 1: Pesquisar atores → Criar profile no Workbench
Dia 2: Exportar Navigator Layer → Compartilhar com equipe
Dia 3: Coletar feedback → Publicar relatório Markdown
Dia 4: Passar para Detection Engineering
```

**Outputs Esperados:**
- ✅ Arquivo JSON (Navigator Layer)
- ✅ Arquivo Markdown (Threat Report)
- ✅ Link compartilhável do Navigator

---

### 🟡 Detection Engineer (Engenheiro de Detecção)

**Objetivo:** Construir backlog priorizado de detecções baseado em ameaça

**Arquivos Relevantes:**
1. [detection-engineer/windows-detection-backlog.md](./detection-engineer/windows-detection-backlog.md) ⭐⭐⭐
   - **O quê:** Exemplo COMPLETO de backlog de detecção
   - **Como usar:** Template para seu próprio backlog
   - **Conteúdo:**
     - Técnicas priorizadas por score
     - Regras de detecção com pseudo-código
     - Dados necessários (log sources)
     - Status de implementação
     - KPIs

2. [shared/how-to-use-exports.md](./shared/how-to-use-exports.md)
   - **Seção relevante:** "Export para Backlog (JSON)"
   - **Como usar:** Passo-a-passo para gerar backlog
   - **Conteúdo:** Integração com Jira, Splunk, ferramentas

**Workflow Típico:**
```
Dia 1: Receber profile do CTI → Carregar no Workbench
Dia 2: Aplicar telemetria (Windows, Sysmon, etc)
Dia 3: Exportar Detection Backlog (JSON)
Dia 4: Criar tickets no Jira (automático ou manual)
Dia 5-10: Construir 3-5 regras de detecção
```

**Outputs Esperados:**
- ✅ Arquivo JSON (Detection Backlog)
- ✅ Tickets no Jira/Azure DevOps
- ✅ Regras de detecção em SIEM
- ✅ Documentação em Markdown

---

### 🔵 SOC Lead (Líder de SOC)

**Objetivo:** Relatório mensal de cobertura, KPIs, ROI e blind spots

**Arquivos Relevantes:**
1. [soc-lead/monthly-coverage-report.md](./soc-lead/monthly-coverage-report.md) ⭐⭐⭐⭐
   - **O quê:** Exemplo completo de relatório mensal
   - **Como usar:** Template para seus relatórios
   - **Conteúdo:**
     - Sumário executivo com métricas
     - Cobertura por tática
     - Análise de blind spots
     - ROI de mitigações
     - Roadmap de investimento
     - Requisitos de orçamento

2. [shared/how-to-use-exports.md](./shared/how-to-use-exports.md)
   - **Seção relevante:** "Pattern 2: SOC Coverage Review (Monthly)"
   - **Como usar:** Fluxo mensal de coleta e análise

**Workflow Típico:**
```
1º dia do mês: Carregar threat profile no Workbench
Dia 2: Aplicar telemetria ATUAL (Windows, Cloud, etc)
Dia 3: Exportar relatório (Matrix view)
Dia 4: Analisar blind spots
Dia 5: Calcular ROI de investimentos
Dia 6: Preparar slide deck
Dia 7: Apresentar à liderança + solicitar orçamento
```

**Outputs Esperados:**
- ✅ Arquivo Markdown (Monthly Report)
- ✅ CSV com KPIs (para dashboard)
- ✅ Gráficos de cobertura
- ✅ Proposta de orçamento

---

## 🔗 Fluxo de Trabalho Completo

```
┌─────────────────────────────────────────────────────────────┐
│                     CTI ANALYST                             │
│  1. Pesquisa ator (APT29)                                  │
│  2. Carrega no Workbench                                   │
│  3. Exporta: threat-actor-profile.md + navigator-layer.json│
│                          ↓                                  │
├─────────────────────────────────────────────────────────────┤
│              TEAM REVIEW (Slack, Wiki)                     │
│  • Técnicas confirmadas?                                   │
│  • Preocupações regionais?                                 │
│  • Atualizar intelligence                                  │
│                          ↓                                  │
├─────────────────────────────────────────────────────────────┤
│             DETECTION ENGINEER                             │
│  1. Carrega profile no Workbench                           │
│  2. Aplica telemetria: Windows, Sysmon, CloudTrail        │
│  3. Exporta: detection-backlog.json                        │
│  4. Cria 5-10 tickets Jira (automático)                   │
│  5. Implementa regras de detecção                          │
│                          ↓                                  │
├─────────────────────────────────────────────────────────────┤
│               SOC LEAD (Monthly)                           │
│  1. Carrega profile                                        │
│  2. Avalia coverage %                                      │
│  3. Identifica blind spots                                 │
│  4. Calcula ROI de investimentos (EDR, PAM, etc)          │
│  5. Apresenta monthly-coverage-report.md à liderança      │
│  6. Solicita orçamento                                     │
│                          ↓                                  │
├─────────────────────────────────────────────────────────────┤
│              LIDERANÇA (Decision Making)                   │
│  • Aprovar orçamento para EDR/XDR?                         │
│  • Contratar mais detection engineers?                     │
│  • Escalar para C-level?                                   │
│                          ↓                                  │
├─────────────────────────────────────────────────────────────┤
│         PRÓXIMO MÊS (Iteração)                             │
│  • Cobertura melhorou?                                     │
│  • Novos blind spots?                                      │
│  • Novos adversários na ameaça landscape?                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 📊 Métricas que Cada Persona Acompanha

### 🔴 CTI Analyst
- ✅ # de atores perfilados
- ✅ # de técnicas por ator
- ✅ Overlap % entre atores
- ✅ Técnicas emergentes detectadas

### 🟡 Detection Engineer
- ✅ Cobertura % (técnicas detectadas)
- ✅ Regras implementadas
- ✅ Taxa de falso positivo (< 2%)
- ✅ Mean Time to Detect (MTTD)
- ✅ Blind spots restantes

### 🔵 SOC Lead
- ✅ Cobertura por tática
- ✅ Blind spots por tática
- ✅ ROI de mitigações
- ✅ Tendência mensal (↑ ou ↓)
- ✅ Custo evitado (prevented breach cost)

---

## 🚀 Como Usar Este Repositório de Exemplos

### Opção 1: Copiar Estrutura
```bash
# Copie threat-actor-profile.md como template
cp cti-analyst/threat-actor-profile.md ~/my-threat-actors/apt29-profile.md

# Edite com seus dados
nano ~/my-threat-actors/apt29-profile.md
```

### Opção 2: Integrar com Git
```bash
# Clone o Workbench
git clone https://github.com/you/attack-analysis-workbench.git

# Suas profiles ficam versionadas
cd attack-analysis-workbench/docs/examples
cp cti-analyst/threat-actor-profile.md ../../threat-profiles/2025-06-apt29.md
git add threat-profiles/2025-06-apt29.md
git commit -m "Add APT29 profile — Q2 2025"
```

### Opção 3: Exportar Automaticamente
```bash
# Use a API para gerar automaticamente
workbench-cli export \
  --profile "APT29" \
  --format markdown \
  --output ~/reports/apt29-profile.md
```

---

## 💡 Dicas Práticas

### ✅ RECOMENDADO
- ✅ Atualize profiles mensalmente (inteligência muda)
- ✅ Version control seus exports (git commit)
- ✅ Automate a geração de backlog (reduz tempo manual)
- ✅ Documente suas suposições (por que score = X?)
- ✅ Compartilhe Navigator layers via deeplinks
- ✅ Colabara entre equipes (ping CTI no Slack)

### ❌ EVITE
- ❌ Deixar exports desatualizados
- ❌ Armazenar dados sensíveis em profiles públicos
- ❌ Usar scores sem documentação
- ❌ Esquecimento de atualizar KPIs
- ❌ Silos entre CTI/Detection/SOC

---

## 📞 Dúvidas Frequentes

**P: Como atualizo os dados do ATT&CK?**  
R: O arquivo `data/attack-data.json` deve ser atualizado mensalmente. Execute:
```bash
python scripts/build_data.py  # Busca dados frescos do ATT&CK
```

**P: Posso compartilhar Navigator layers externamente?**  
R: Sim, mas verifique primeiro se há dados sensíveis. Links do Navigator expiram após ~30 dias.

**P: Como integro com meu SIEM?**  
R: Veja [shared/how-to-use-exports.md](./shared/how-to-use-exports.md) → "Integration Examples"

**P: Qual é o melhor score para detectar?**  
R: Recomendamos iniciar com score ≥ 70 (técnicas críticas), expandir para ≥ 50 depois.

**P: Posso ter múltiplos profiles?**  
R: Sim! Crie múltiplos profiles e compare:
```
Profile A: Top 10 global APTs
Profile B: Adversários regionais
Profile C: Adversários específicos do seu setor
```

---

## 📋 Checklist: Primeiro Uso

- [ ] Li [README.md](./README.md)
- [ ] Escolhi minha persona (CTI/Detection/SOC)
- [ ] Li o exemplo correspondente
- [ ] Criei um threat profile no Workbench
- [ ] Exportei em um formato (Navigator/Backlog/Markdown)
- [ ] Compartilhei com minha equipe
- [ ] Configurei um workflow automático (opcional)
- [ ] Salvei em version control (git)

---

## 🔄 Próximas Adições Planejadas

```
v2.1 (Próximo mês):
  ✓ linux-detection-backlog.md (exemplos para Linux)
  ✓ blind-spots-analysis.md (análise de gaps)
  ✓ mitigation-roi-planning.md (decisões de investimento)
  ✓ Exemplos de integração: Jira, Splunk, Azure DevOps
  
v2.2 (Dentro de 2 meses):
  ✓ API documentation
  ✓ Python SDK para automação
  ✓ Scripts de export automático
  ✓ Dashboard templates (Grafana, PowerBI)
```

---

## 📚 Recursos Adicionais

- **MITRE ATT&CK:** https://attack.mitre.org
- **ATT&CK Navigator:** https://mitre-attack.github.io/attack-navigator/
- **Workbench GitHub:** https://github.com/you/attack-analysis-workbench
- **Este diretório:** `/docs/examples/`

---

## 📝 Feedback & Contribuições

Tem sugestões de exemplos? Encontrou um erro? Abra uma issue ou PR!

```
GitHub Issues: https://github.com/you/attack-analysis-workbench/issues
Pull Requests: https://github.com/you/attack-analysis-workbench/pulls
```

---

**Última Atualização:** 2025-07-08  
**Versão do Workbench:** 2.0 (ES6 Modules + Vite)  
**Versão do ATT&CK:** v13.0+

**Bom proveito! 🚀**
