# Quick Reference — Cheat Sheet

Respostas rápidas para as tarefas mais comuns.

---

## 🎯 Tarefas Rápidas

### "Quero criar um perfil de ameaça"

```
1. Abra o Workbench
2. Search: "APT29" (ou seu ator)
3. Click: "✓ Threat Profile"
4. Repita para mais atores
5. Vá para Matrix tab
6. Click: "Export Navigator Layer"
✅ Pronto! Arquivo JSON gerado
```

**Tempo:** 2 minutos | **Arquivo:** `navigator-layer.json`

---

### "Preciso de um backlog de detecção"

```
1. Carregue threat profile (veja acima)
2. Vá para Detection Designer tab
3. Aplique telemetria: [✓] Windows [✓] Sysmon
4. Click: "Export Backlog"
5. Escolha formato: JSON ou Markdown
✅ Pronto! Backlog gerado
```

**Tempo:** 5 minutos | **Arquivo:** `backlog.json` ou `backlog.md`

---

### "Quero compartilhar com minha equipe"

```
Opção A - Navigator Layer:
1. Export JSON (veja acima)
2. Abra https://mitre-attack.github.io/attack-navigator/
3. Click: "New Layer" → "Import"
4. Click: "Share" → Copie URL
5. Envie para equipe no Slack

Opção B - Git:
1. git add profile.json
2. git commit -m "Add APT29 profile"
3. git push
4. Compartilhe via link: github.com/.../blob/main/profile.json
```

**Tempo:** 3 minutos | **Resultado:** Link compartilhável

---

### "Quero integrar com Jira"

```bash
# Extrair técnicas com score alto
cat backlog.json | jq '.techniques[] | select(.threat_score > 70)' > high-priority.json

# Converter para CSV para importar no Jira
cat high-priority.json | jq -r '.[] | [.id, .name, .total_score] | @csv' > tickets.csv

# Ou automatizar criação de issues (veja docs/examples/shared/how-to-use-exports.md)
```

**Tempo:** 5 minutos | **Resultado:** Tickets automáticos no Jira

---

### "Quero ver cobertura de detecção"

```
1. Carregue threat profile
2. Vá para Detection Designer
3. Aplique telemetria (seus log sources)
4. Veja resumo: "Coverage: 56%"
5. Filtre por "Visibility = Blind"
6. Veja quais dados faltam
```

**Tempo:** 3 minutos | **Resultado:** Relatório visual

---

### "Quero saber quais gaps de detecção fechar primeiro"

```
1. Carregue threat profile
2. Vá para Detection Designer
3. Aplique telemetria (seus log sources)
4. Em "Your detection rules" → "⭱ Import rules…"
   (Sigma YAML, CSV, JSON ou Navigator layer)
5. Veja os cards: "rule coverage %" e "gaps ready to close"
6. Filtre: "Gap + telemetry ready"
   → técnicas sem regra mas com telemetria pronta
7. Abra o card da técnica → "Suggested public rules"
   → regras SigmaHQ prontas, com link para o GitHub
✅ Backlog de gaps priorizados, com regra sugerida para cada um
```

**Tempo:** 5 minutos | **Resultado:** Lista de gaps acionáveis

**Dica:** No Matrix, marque "Rule coverage" para ver o overlay:
verde = coberto por regra sua, tracejado vermelho = usado pelo perfil sem regra.

---

### "Preciso de um relatório para liderança"

```
1. Carregue threat profile
2. Export em Markdown
3. Screenshot do Matrix tab
4. Compile relatório (veja exemplo: docs/examples/soc-lead/monthly-coverage-report.md)
5. Inclua slides:
   - Heatmap (screenshot)
   - KPIs (numbers)
   - Blind spots (threats)
   - ROI (budget ask)
```

**Tempo:** 15 minutos | **Resultado:** Slide deck executivo

---

## 📊 Formatos de Export

| Goal | Format | File | Tool |
|------|--------|------|------|
| Compartilhar com stakeholders | Navigator Layer | `.json` | Browser |
| Criar tickets | Backlog | `.json` | Jira, Excel |
| Documentar | Threat Report | `.md` | Wiki, Confluence |
| Reportar KPIs | Coverage Report | `.md` ou `.csv` | Splunk, PowerBI |

---

## 🎨 Formulas de Score

```javascript
// Como o score é calculado:

threat_score = MIN(50, actors_count * avg_prevalence / 10)
// Ex: 2 actors × 82% = 42

prevalence_score = global_prevalence * 30 / 100
// Ex: 92% × 30 / 100 = 27.6 ≈ 30

exposure_score = has_mitigation ? 0 : 20
// Ex: No mitigation = 20 (detection-only)

total_score = threat_score + prevalence_score + exposure_score
// Ex: 42 + 30 + 20 = 92 🎯
```

---

## 📈 Visibilidade Explicada

```
✅ FULL    = Técnica sempre detectada (100% visibility)
⚠️  PARTIAL = Técnica às vezes detectada (platform-dependent)
❌ BLIND   = Sem detecção (precisa EDR/XDR)

Exemplo:
T1059.001 PowerShell:
  ✅ FULL no Windows (Event 4688)
  ❌ BLIND em Linux (sem PowerShell nativo)
  = Resultado: PARTIAL
```

---

## 🔄 Fluxo Semanal (Detection Engineer)

```
SEGUNDA:     Load threat profile → Set telemetry → Import rule inventory
TERÇA:       Filter "Gap + telemetry ready" → Export backlog → Jira tickets (top 10)
QUARTA-5ª:   Build 2-3 detection rules (partindo das sugestões SigmaHQ)
SEXTA:       Test + fine-tune rules → Deploy → Re-import inventory (coverage sobe)
```

---

## 📅 Fluxo Mensal (SOC Lead)

```
Dia 1:  Load profile → Check coverage %
Dia 2:  Identify blind spots → List gaps
Dia 3:  Calculate ROI → Draft recommendations
Dia 4:  Prepare slides → Schedule meeting
Dia 5:  Present to leadership → Request budget
```

---

## ❓ Perguntas Rápidas

**P: Qual score devo usar?**  
R: `score ≥ 70` = CRÍTICO (comece aqui) | `50-70` = ALTO | `<50` = MÉDIO

**P: Como atualizo mensal?**  
R: `python scripts/build_data.py` → Dados novos do ATT&CK

**P: Posso ter múltiplos profiles?**  
R: Sim! Crie um novo → Exporte separado

**P: EDR/XDR resolve blind spots?**  
R: Sim, resolve ~70% deles (behavior analysis)

**P: Como calibro false positives?**  
R: Tuning iterativo: regra → alertas → investigar → ajustar

---

## 🛠️ Troubleshooting Rápido

| Problema | Solução |
|----------|---------|
| Search não encontra ator | Use ATT&CK ID: `G0016` |
| JSON não importa no Navigator | Valide: `jq . < backlog.json` |
| Score não faz sentido | Veja documentação no campo |
| Telemetria não aparece | Refresh: Ctrl+Shift+Del |
| Backlog muito grande | Filtre: `threat_score > 70` |

---

## 📚 Links Essenciais

| Recurso | Link | Uso |
|---------|------|-----|
| ATT&CK Técnicas | https://attack.mitre.org | Reference |
| Navigator | https://mitre-attack.github.io/attack-navigator/ | Share layers |
| Workbench | Este repo | Exportar |
| Exemplos | `/docs/examples/` | Copiar template |

---

## 💾 Dúvida: Onde Salvar?

```
Arquivos importantes:
├── threat-profiles/          # Markdown reports
├── navigator-layers/         # JSON layers
├── detection-backlogs/       # JSON backlogs
├── coverage-reports/         # Monthly KPIs
└── detection-rules/          # Regras em SIEM
```

---

## ⚡ Pro Tips

💡 **Tip 1:** Use `share` button no Navigator para criar URL — mais rápido que email

💡 **Tip 2:** Exporte mensal com versão: `backlog-2025-06-v1.json`

💡 **Tip 3:** Filtre por `visibility = "Blind"` para priorizar lacunas

💡 **Tip 4:** Coloque score em título de ticket Jira: `T1059.001 PowerShell [98]`

💡 **Tip 5:** Use `jq` para filtros rápidos:
```bash
cat backlog.json | jq '.techniques[] | select(.visibility == "Blind")'
```

---

**Última atualização:** 2025-07-08  
**Versão:** 2.0  
**Para dúvidas completas:** Veja `/docs/examples/shared/how-to-use-exports.md`
