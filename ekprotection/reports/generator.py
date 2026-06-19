"""
ekprotection.reports.generator
================================
Gerador de relatórios de segurança exportáveis.

Formatos suportados:
  - JSON  — dados brutos estruturados
  - HTML  — relatório visual com logo EKP e tabelas
  - TXT   — sumário em texto puro (para e-mail / syslog)

O relatório agrega:
  - Sumário executivo (totais, período, nível de risco geral)
  - Ameaças detectadas (scanner + heurísticas)
  - Eventos de quarentena
  - Estatísticas de logs por tipo
  - Status dos subsistemas
  - Timeline de eventos (últimas 24h)
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from pathlib  import Path
from typing   import Any, Optional


class ReportGenerator:
    """
    Gera relatórios de segurança a partir dos dados dos subsistemas.

    Uso:
        gen = ReportGenerator(config, log_mgr, quar_mgr, scan_engine)
        gen.generate(output_path, fmt="html")
    """

    def __init__(
        self,
        config:      Any,
        log_manager: Any  = None,
        quar_manager:Any  = None,
        scan_engine: Any  = None,
        exc_manager: Any  = None,
    ) -> None:
        self.config  = config
        self._log    = log_manager
        self._quar   = quar_manager
        self._scan   = scan_engine
        self._exc    = exc_manager

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def generate(
        self,
        output_path: str | Path,
        fmt:         str   = "html",
        since_hours: int   = 24,
        title:       str   = "EK-Protection — Relatório de Segurança",
    ) -> Path:
        """
        Gera relatório e salva em output_path.
        fmt: "html" | "json" | "txt"
        Retorna Path do arquivo gerado.
        """
        data = self._collect_data(since_hours)
        out  = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)

        fmt = fmt.lower()
        if fmt == "json":
            self._write_json(out, data)
        elif fmt == "txt":
            self._write_txt(out, data, title)
        else:
            self._write_html(out, data, title)

        return out

    # ------------------------------------------------------------------
    # Coleta de dados
    # ------------------------------------------------------------------

    def _collect_data(self, since_hours: int) -> dict[str, Any]:
        since = datetime.utcnow() - timedelta(hours=since_hours)
        data: dict[str, Any] = {
            "generated_at": datetime.utcnow().isoformat(),
            "since":        since.isoformat(),
            "since_hours":  since_hours,
            "version":      "1.0.0",
        }

        # --- Logs ---
        if self._log:
            try:
                from ekprotection.logs.models import QueryFilter, LogLevel, EventType
                stats = self._log.stats()
                data["log_stats"]   = stats
                data["log_total"]   = stats.get("total_entries", 0)

                # Ameaças nos logs
                threats = self._log.query(QueryFilter(
                    event_type = EventType.THREAT_DETECTED,
                    since      = since,
                    limit      = 500,
                ))
                data["threat_events"] = [e.to_dict() for e in threats]
                data["threat_count"]  = len(threats)

                # Timeline: todos os eventos das últimas since_hours
                timeline = self._log.query(QueryFilter(
                    since = since, limit = 200, order_desc = False
                ))
                data["timeline"] = [e.to_dict() for e in timeline]

                # Contagem por nível
                data["by_level"] = stats.get("by_level", {})
            except Exception as e:
                data["log_error"] = str(e)

        # --- Quarentena ---
        if self._quar:
            try:
                qstats = self._quar.stats()
                active = self._quar.list_active()
                data["quarantine_stats"]  = qstats
                data["quarantine_active"] = [e.to_dict() for e in active[:50]]
            except Exception as e:
                data["quarantine_error"] = str(e)

        # --- Exceções ---
        if self._exc:
            try:
                data["exceptions_status"] = self._exc.status()
            except Exception as e:
                data["exceptions_error"] = str(e)

        # --- Risk level geral ---
        threat_count = data.get("threat_count", 0)
        quar_active  = data.get("quarantine_stats", {}).get("active", 0)

        if threat_count >= 10 or quar_active >= 5:
            data["overall_risk"] = "crítico"
        elif threat_count >= 3 or quar_active >= 2:
            data["overall_risk"] = "alto"
        elif threat_count >= 1 or quar_active >= 1:
            data["overall_risk"] = "médio"
        else:
            data["overall_risk"] = "limpo"

        return data

    # ------------------------------------------------------------------
    # Renderizadores
    # ------------------------------------------------------------------

    def _write_json(self, path: Path, data: dict) -> None:
        path.write_text(
            json.dumps(data, ensure_ascii=False, indent=2, default=str),
            encoding="utf-8",
        )

    def _write_txt(self, path: Path, data: dict, title: str) -> None:
        lines = [
            "=" * 70,
            f"  {title}",
            "=" * 70,
            f"  Gerado em:     {data['generated_at']}",
            f"  Período:       Últimas {data['since_hours']}h",
            f"  Versão:        EK-Protection {data['version']}",
            "",
            "── SUMÁRIO EXECUTIVO ──────────────────────────────────────────────",
            f"  Risco geral:   {data.get('overall_risk','?').upper()}",
            f"  Ameaças:       {data.get('threat_count', 0)}",
            f"  Em quarentena: {data.get('quarantine_stats',{}).get('active', 0)}",
            f"  Logs total:    {data.get('log_total', 0)}",
            "",
        ]

        threats = data.get("threat_events", [])
        if threats:
            lines += ["── AMEAÇAS DETECTADAS ─────────────────────────────────────────────"]
            for t in threats[:20]:
                ts   = t.get("timestamp", "")[:19]
                msg  = t.get("message",   "")[:60]
                fp   = t.get("file_path", "") or ""
                lines.append(f"  [{ts}] {msg}")
                if fp:
                    lines.append(f"            {fp}")
            lines.append("")

        quar = data.get("quarantine_active", [])
        if quar:
            lines += ["── QUARENTENA ATIVA ───────────────────────────────────────────────"]
            for q in quar[:10]:
                lines.append(
                    f"  #{q.get('id','')}  {q.get('original_path','')}  "
                    f"[{q.get('risk_level','?')}]  {q.get('reason','')}"
                )
            lines.append("")

        lines += ["=" * 70, "  Fim do relatório EK-Protection", "=" * 70]
        path.write_text("\n".join(lines), encoding="utf-8")

    def _write_html(self, path: Path, data: dict, title: str) -> None:
        """Gera relatório HTML com logo EKP e tabelas responsivas."""
        # Pre-compute values to avoid dict literals inside f-strings
        quar_stats  = data.get("quarantine_stats") or {}
        exc_status  = data.get("exceptions_status") or {}
        quar_active_count = quar_stats.get("active", 0)
        exc_whitelist     = exc_status.get("whitelist", 0)

        # Localiza logo (base64 inline para portabilidade)
        logo_b64 = ""
        assets_candidates = [
            Path(__file__).parent.parent.parent / "assets" / "logo.png",
            Path(os.environ.get("EKP_DATA_DIR", "/var/lib/ek-protection")) / "assets" / "logo.png",
        ]
        for lp in assets_candidates:
            if lp.exists():
                import base64
                logo_b64 = base64.b64encode(lp.read_bytes()).decode()
                break

        risk        = data.get("overall_risk", "limpo")
        risk_colors = {
            "crítico": "#dc2626",
            "alto":    "#ea580c",
            "médio":   "#ca8a04",
            "limpo":   "#16a34a",
        }
        risk_color  = risk_colors.get(risk, "#6b7280")
        threats     = data.get("threat_events", [])
        quar_active = data.get("quarantine_active", [])
        timeline    = data.get("timeline", [])
        by_level    = data.get("by_level", {})

        def rows(items: list, keys: list[str]) -> str:
            if not items:
                return f'<tr><td colspan="{len(keys)}" class="empty">Nenhum registro.</td></tr>'
            html = ""
            for item in items[:50]:
                html += "<tr>" + "".join(
                    f"<td>{str(item.get(k, '—'))[:80]}</td>" for k in keys
                ) + "</tr>"
            return html

        logo_tag = (
            f'<img src="data:image/png;base64,{logo_b64}" alt="EKP Logo" class="logo">'
            if logo_b64 else '<span class="logo-text">EKP</span>'
        )

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  :root {{
    --bg:      #09090b;
    --card:    #111113;
    --border:  #222226;
    --text:    #e4e4e7;
    --muted:   #71717a;
    --amber:   #f5a623;
    --risk:    {risk_color};
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text);
          font-family: 'Segoe UI', system-ui, monospace; padding: 2rem; }}
  header {{ display: flex; align-items: center; gap: 1.5rem;
             border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .logo {{ width: 72px; height: 72px; object-fit: contain; }}
  .logo-text {{ font-size: 2rem; font-weight: 900; color: var(--amber); }}
  header h1 {{ font-size: 1.4rem; color: var(--text); }}
  header .meta {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.25rem; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px,1fr));
            gap: 1rem; margin-bottom: 2rem; }}
  .kpi {{ background: var(--card); border: 1px solid var(--border);
           border-radius: 8px; padding: 1.25rem; }}
  .kpi .label {{ font-size: 0.75rem; color: var(--muted); text-transform: uppercase;
                  letter-spacing: 0.05em; margin-bottom: 0.4rem; }}
  .kpi .value {{ font-size: 2rem; font-weight: 700; color: var(--amber); }}
  .kpi .risk-value {{ color: var(--risk); }}
  section {{ background: var(--card); border: 1px solid var(--border);
              border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
  section h2 {{ font-size: 1rem; font-weight: 600; color: var(--amber);
                 margin-bottom: 1rem; letter-spacing: 0.02em; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; }}
  th {{ text-align: left; color: var(--muted); font-weight: 500;
         padding: 0.4rem 0.75rem; border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.45rem 0.75rem; border-bottom: 1px solid var(--border);
         color: var(--text); word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .empty {{ color: var(--muted); text-align: center; padding: 1.5rem; font-style: italic; }}
  .badge {{ display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px;
             font-size: 0.72rem; font-weight: 600; text-transform: uppercase; }}
  .badge-crítico {{ background: #dc262620; color: #dc2626; }}
  .badge-alto     {{ background: #ea580c20; color: #ea580c; }}
  .badge-médio    {{ background: #ca8a0420; color: #ca8a04; }}
  .badge-baixo    {{ background: #16a34a20; color: #16a34a; }}
  .badge-limpo    {{ background: #16a34a20; color: #16a34a; }}
  footer {{ text-align: center; color: var(--muted); font-size: 0.75rem;
             margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
</style>
</head>
<body>
<header>
  {logo_tag}
  <div>
    <h1>{title}</h1>
    <div class="meta">
      Gerado em {data['generated_at'][:19].replace('T',' ')} UTC
      &nbsp;·&nbsp; Período: últimas {data['since_hours']}h
      &nbsp;·&nbsp; EK-Protection v{data['version']}
    </div>
  </div>
</header>

<div class="grid">
  <div class="kpi">
    <div class="label">Risco Geral</div>
    <div class="value risk-value">{risk.upper()}</div>
  </div>
  <div class="kpi">
    <div class="label">Ameaças</div>
    <div class="value">{data.get('threat_count',0)}</div>
  </div>
  <div class="kpi">
    <div class="label">Em Quarentena</div>
    <div class="value">{quar_active_count}</div>
  </div>
  <div class="kpi">
    <div class="label">Eventos (log)</div>
    <div class="value">{data.get('log_total',0)}</div>
  </div>
  <div class="kpi">
    <div class="label">Whitelist</div>
    <div class="value">{exc_whitelist}</div>
  </div>
</div>

<section>
  <h2>⚠ Ameaças Detectadas</h2>
  <table>
    <thead><tr>
      <th>Timestamp</th><th>Mensagem</th><th>Arquivo</th><th>Hash</th>
    </tr></thead>
    <tbody>
      {rows(threats, ["timestamp","message","file_path","sha256"])}
    </tbody>
  </table>
</section>

<section>
  <h2>🔒 Quarentena Ativa</h2>
  <table>
    <thead><tr>
      <th>ID</th><th>Arquivo</th><th>Risco</th><th>Motivo</th><th>Data</th>
    </tr></thead>
    <tbody>
      {rows(quar_active, ["id","original_path","risk_level","reason","quarantined_at"])}
    </tbody>
  </table>
</section>

<section>
  <h2>📊 Logs por Nível</h2>
  <table>
    <thead><tr><th>Nível</th><th>Quantidade</th></tr></thead>
    <tbody>
      {"".join(
        f'<tr><td><span class="badge badge-{lvl.lower()}">{lvl}</span></td>'
        f'<td>{cnt}</td></tr>'
        for lvl, cnt in by_level.items()
      ) or '<tr><td colspan="2" class="empty">Sem dados.</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>📅 Timeline de Eventos</h2>
  <table>
    <thead><tr>
      <th>Timestamp</th><th>Nível</th><th>Tipo</th><th>Origem</th><th>Mensagem</th>
    </tr></thead>
    <tbody>
      {rows(timeline, ["timestamp","level","event_type","source","message"])}
    </tbody>
  </table>
</section>

<footer>
  EK-Protection v{data['version']} &nbsp;·&nbsp; EviRyKorp &nbsp;·&nbsp;
  Relatório gerado automaticamente — não compartilhar externamente.
</footer>
</body>
</html>"""

        path.write_text(html, encoding="utf-8")
