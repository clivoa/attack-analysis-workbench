# Attack Analysis Workbench — Export Examples

Este diretório contém exemplos de planos e relatórios gerados pelo **Attack Analysis Workbench**, demonstrando como as informações estruturadas do MITRE ATT&CK podem ser utilizadas em diferentes contextos operacionais.

## 📂 Estrutura

```
examples/
├── README.md (este arquivo)
├── cti-analyst/
│   ├── threat-actor-profile.md
│   └── navigator-layer-guide.md
├── detection-engineer/
│   ├── windows-detection-backlog.md
│   ├── linux-detection-backlog.md
│   └── using-detection-cards.md
├── soc-lead/
│   ├── monthly-coverage-report.md
│   ├── blind-spots-analysis.md
│   └── mitigation-roi-planning.md
└── shared/
    ├── how-to-use-exports.md
    └── data-model-reference.md
```

## 👥 Personas & Workflows

### 1. **CTI Analyst** 🔍
**Objetivo:** Documentar adversários, seus TTPs e compartilhar inteligência com os times operacionais.

**Exporta:**
- Dossiers de grupos/campanhas
- Navigator Layers (ATT&CK Heatmap em JSON)
- Perfis de sobreposição (técnicas compartilhadas entre atores)

**Usa para:**
- Relatórios de ameaça para executivos
- Briefings técnicos para SOC/Detection
- Compartilhamento inter-equipes
- Auditorias e compliance

---

### 2. **Detection Engineer** 🛠️
**Objetivo:** Construir backlogs de detecção priorizados com base em ameaça e telemetria disponível.

**Exporta:**
- Cartas de detecção em Markdown (técnica + contexto + dados necessários)
- Backlog em JSON (para piping em ferramentas de ticketing)
- Listas filtradas por visibilidade (Full/Partial/Blind)

**Usa para:**
- Planejamento de regras de detecção
- Justificativa de onboarding de dados
- Rastreamento de progresso
- Documentação de analytics

---

### 3. **SOC Lead** 👔
**Objetivo:** Tomar decisões de investimento e reportar cobertura à liderança.

**Exporta:**
- Resumos de cobertura (% de técnicas detectadas)
- Análise de blind spots (onde há apenas detecção, sem mitigação)
- ROI de mitigações (impacto potencial vs. esforço)
- KPIs para dashboard

**Usa para:**
- Orçamento e alocação de recursos
- Relatórios executivos
- Justificativa de ferramental
- Estratégia de resposta à ameaça

---

## 🔗 Como Usar Este Workbench

### Workflow: De Ameaça a Detecção

```
1. CTI fornece ameaça (grupos/campanhas)
   ↓
2. Detection Engineer carrega profile
   ↓
3. Aplica telemetria disponível
   ↓
4. Exporta Detection Backlog
   ↓
5. Prioriza por score (threat + prevalence + exposure)
   ↓
6. Constrói regras em SIEM/EDR
   ↓
7. SOC Lead rastreia cobertura e ROI
```

### Principais Exports

#### **Navigation Layer (JSON)**
```json
{
  "version": "4.4",
  "name": "APT29 + Lazarus Group Heatmap",
  "techniques": [
    { "techniqueID": "T1053.005", "color": "#FF6B6B", "score": 42 }
  ]
}
```
👉 Use em: https://mitre-attack.github.io/attack-navigator/

#### **Detection Card (Markdown)**
```markdown
## T1053.005 — Scheduled Task

**Ameaça:** APT29 (43%), Lazarus Group (38%), 14 grupos total
**Prevalência Global:** 89% (muito comum)
**Mitigação:** M1026 (Privileged Account Management) — Cobertura parcial
**Telemetria Necessária:**
  - ✅ Windows Security Event (Task Scheduler: 106, 140, 141)
  - ❌ Sysmon (não configurado)
  - ✅ PowerShell transcription logs

**Analytics (MITRE):**
1. Scheduled Task Creation — EventID 106 + Command > 500 chars
2. Suspicious Scheduled Task Deletion — Rapid task cleanup pattern
3. SYSTEM context execution — Non-standard tasks running as SYSTEM
```

#### **Detection Backlog (JSON)**
```json
{
  "techniques": [
    {
      "id": "T1053.005",
      "name": "Scheduled Task",
      "threat_score": 42,
      "prevalence_score": 30,
      "exposure_score": 20,
      "total_score": 92,
      "visibility": "Partial",
      "status": "planned",
      "required_log_sources": ["WinEventLog:Security", "Sysmon"],
      "mitigations": ["M1026"]
    }
  ]
}
```

---

## 🎯 Casos de Uso Práticos

### Caso 1: CTI → Detection
**Cenário:** CTI descobre APT29 atacando setor financeiro.
1. ✏️ CTI monta profile em workbench (APT29)
2. 📊 Exporta Navigator Layer + relatório Markdown
3. 👀 Detection Engineer carrega o perfil
4. 🔧 Verifica visibilidade contra telemetria Windows existente
5. 📝 Exporta Detection Backlog priorizado
6. 🎯 Equipe começa regras pelos itens de alto score

**Resultado:** Cobertura focada em 72h, não em 3 meses.

### Caso 2: Blind Spot Discovery
**Cenário:** SOC quer saber onde está desprotegido.
1. 👔 SOC Lead carrega threat profile (Top 10 adversários regionais)
2. 📊 Aplica telemetria real (Windows + Linux + Cloud)
3. 🔍 Filtra técnicas com visibilidade "Blind"
4. 📋 Exporta lista de blind spots por tática
5. 💡 Para cada blind spot, examina mitigação vs. detecção

**Resultado:** ROI claro: "Precisamos de EDR em Linux para cobrir 23 técnicas críticas".

### Caso 3: Compliance & Auditing
**Cenário:** Auditores perguntam: "Vocês cobrem esses adversários?"
1. 🔒 Compila threat profile (seus adversários conhecidos)
2. 📊 Exporta Navigator Layer + relatório JSON
3. 📎 Anexa ao relatório de audit
4. ✅ Prova técnica de cada técnica vs. controle

**Resultado:** Evidência documentada, fácil de revisar anualmente.

---

## 📥 Como Exportar do Workbench

### Detection Engineer → Markdown Card
1. Abra a aba **Detection Designer**
2. Filtre por threat profile e telemetria desejada
3. Clique em um card de técnica para ler a description completa
4. Copie o conteúdo ou use **Export → Markdown**

### Detection Engineer → JSON Backlog
1. Aba **Detection Designer** → **Export → JSON**
2. Salve localmente: `backlog-2025-07.json`
3. Pipe para sua ferramenta de ticketing:
```bash
cat backlog.json | jq '.techniques | .[] | select(.threat_score > 50)' | ...
```

### CTI Analyst → Navigator Layer
1. Aba **Matrix** (com threat profile montado)
2. Clique **Export Navigator Layer**
3. Abre https://mitre-attack.github.io/attack-navigator
4. Paste JSON → Visualize → Compartilhe link

---

## 📊 Estrutura de Dados (Referência)

```javascript
{
  "technique": {
    "id": "T1053.005",
    "name": "Scheduled Task/Job",
    "tactics": ["Execution", "Persistence"],
    
    "threat_profile": {
      "actors_using": ["G0016", "G0032"],  // APT29, Lazarus
      "prevalence_percent": 89,
      "campaigns": 142
    },
    
    "detection": {
      "telemetry_required": ["WinEventLog:Security"],
      "telemetry_available": ["WinEventLog:Security"],  // from your settings
      "visibility": "Full",  // Full | Partial | Blind
      "analytics": [
        { "id": "CAR-2013-01-002", "name": "Suspicious Scheduled Task", "sources": ["Sysmon"] }
      ]
    },
    
    "mitigation": {
      "mitigating_controls": ["M1026"],
      "coverage": "Partial",
      "is_detection_only": false  // true means no mitigation exists
    },
    
    "backlog": {
      "status": "planned",  // review | planned | done | na
      "priority_score": 92,
      "last_updated": "2025-07-08"
    }
  }
}
```

---

## 🚀 Próximos Passos

1. **Explore os exemplos** em cada subpasta (`cti-analyst/`, `detection-engineer/`, `soc-lead/`)
2. **Use `shared/how-to-use-exports.md`** para guia prático passo-a-passo
3. **Consulte `shared/data-model-reference.md`** para entender a estrutura de dados
4. **Adapte os templates** aos seus processos

---

## 📞 Dúvidas Frequentes

**P: Como compartilho um Navigator Layer com minha equipe?**
R: Exporte o JSON do workbench → Abra https://mitre-attack.github.io/attack-navigator → Paste JSON → Clique em "Share" → Copie URL.

**P: Posso pipar o backlog JSON diretamente no Jira?**
R: Sim! Use um script de integração (veja `examples/shared/how-to-use-exports.md`).

**P: Qual formato é melhor para relatórios executivos?**
R: Markdown para técnicos, PNG/PDF (print do workbench) para executivos.

**P: Como atualizo os dados do ATT&CK?**
R: O workbench busca `attack-data.json` do diretório `/data/`. Atualize mensalmente.

---

**Last Updated:** 2025-07-08  
**ATT&CK Version:** v13.0+  
**Workbench Version:** 2.0 (ES6 Modules + Vite)
