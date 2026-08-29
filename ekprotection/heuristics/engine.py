"""
ekprotection.heuristics.engine
================================
Motor de análise heurística do EK-Protection.

Responsabilidades:
  - Construir HeuristicContext a partir de um arquivo
  - Avaliar todas as regras ativas sobre o contexto
  - Calcular RiskScore ponderado
  - Produzir HeuristicResult com veredicto, score, matches e evidências
  - Integrar com ExceptionManager, LogManager e o ScanEngine (Patch 7)

Fluxo:
  analyze(path) →
    _build_context(path) →
      _evaluate_rules(ctx) →
        score = Σ (weight × match) / max_possible × 100
        risk  = thresholds[score]
    → HeuristicResult

Thresholds de score (configuráveis):
  0–19:  limpo
  20–39: baixo
  40–59: médio
  60–79: alto
  80+:   crítico
"""

from __future__ import annotations

import logging
import os
import stat as stat_mod
import time
from dataclasses import dataclass, field
from pathlib     import Path
from typing      import Any, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.logs.models    import EventType, LogLevel

from .rules import (
    ALL_RULES, RULES_BY_ID,
    HeuristicContext, HeuristicRule, RuleMatch,
)

logger = logging.getLogger(__name__)

CONTENT_SAMPLE_SIZE = 65_536   # 64KB para análise de conteúdo

# Thresholds de score → risk_level
_SCORE_THRESHOLDS = [
    (80, "crítico"),
    (60, "alto"),
    (40, "médio"),
    (20, "baixo"),
    (0,  None),      # limpo
]

# Ordem de severidade, pro piso de severidade (ver _calculate_score)
_SEVERITY_RANK = {None: 0, "baixo": 1, "médio": 2, "alto": 3, "crítico": 4}


@dataclass(frozen=True)
class HeuristicResult:
    """Resultado completo de análise heurística de um arquivo."""
    path:        str
    score:       float                  # 0–100
    risk_level:  Optional[str]          # None = limpo
    matches:     tuple[RuleMatch, ...]
    rules_fired: tuple[str, ...]        # rule_ids das regras que dispararam
    confidence:  float                  # 0–1 (proporção de regras avaliáveis que foram avaliadas)
    analysis_ms: int
    context_summary: dict               # resumo do contexto para logs/relatório

    @property
    def is_suspicious(self) -> bool:
        return self.risk_level is not None

    @property
    def is_critical(self) -> bool:
        return self.risk_level == "crítico"

    @property
    def primary_reason(self) -> Optional[str]:
        """Motivo principal (regra de maior peso que disparou)."""
        if not self.matches:
            return None
        top = max(
            self.rules_fired,
            key=lambda rid: RULES_BY_ID[rid].weight if rid in RULES_BY_ID else 0,
        )
        rule = RULES_BY_ID.get(top)
        if rule is None:
            return None
        # Encontra o match desse rule
        for m in self.matches:
            if m.rule_id == top:
                return f"{rule.name}: {m.detail}"
        return rule.name

    def to_dict(self) -> dict:
        return {
            "path":         self.path,
            "score":        round(self.score, 2),
            "risk_level":   self.risk_level,
            "rules_fired":  list(self.rules_fired),
            "confidence":   round(self.confidence, 3),
            "analysis_ms":  self.analysis_ms,
            "matches": [
                {
                    "rule_id":  m.rule_id,
                    "detail":   m.detail,
                    "evidence": m.evidence,
                }
                for m in self.matches
            ],
            **self.context_summary,
        }


class HeuristicEngine:
    """
    Motor heurístico do EK-Protection.

    Avalia 22 regras sobre o contexto de cada arquivo e produz
    um RiskScore ponderado.

    Integrado ao ScanEngine via analyze_scan_result() —
    chamado automaticamente pelo ScanEngine no Patch 8.
    """

    def __init__(
        self,
        config:      ConfigManager,
        exc_manager: Any = None,
        log_manager: Any = None,
    ) -> None:
        self.config      = config
        self._exc        = exc_manager
        self._log        = log_manager
        self._sensitivity = config.get("heuristics.sensitivity", "medium")
        self._enabled    = config.get("heuristics.enabled", True)

        # Carrega regras ativas (todas por padrão; desabilitáveis via config)
        disabled = set(config.get("heuristics.disabled_rules", []))
        self._rules = [r for r in ALL_RULES if r.rule_id not in disabled]
        logger.debug("HeuristicEngine: %d regras ativas.", len(self._rules))

    # ------------------------------------------------------------------
    # API principal
    # ------------------------------------------------------------------

    def analyze(self, path: str | Path) -> HeuristicResult:
        """
        Analisa um arquivo com todas as regras heurísticas.
        Nunca lança exceção — erros internos resultam em score 0.
        """
        if not self._enabled:
            return self._empty_result(str(path))

        t0 = time.monotonic()
        path_str = str(path)

        try:
            ctx = self._build_context(path_str)
        except Exception as exc:
            logger.debug("Erro ao construir contexto para %s: %s", path_str, exc)
            return self._empty_result(path_str)

        matches, rules_fired = self._evaluate_rules(ctx)
        score, risk          = self._calculate_score(matches)
        confidence           = self._confidence(ctx)

        result = HeuristicResult(
            path            = path_str,
            score           = score,
            risk_level      = risk,
            matches         = tuple(matches),
            rules_fired     = tuple(rules_fired),
            confidence      = confidence,
            analysis_ms     = int((time.monotonic() - t0) * 1000),
            context_summary = self._ctx_summary(ctx),
        )

        if result.is_suspicious:
            self._log_result(result)

        return result

    def analyze_bytes(self, path: str, content: bytes) -> HeuristicResult:
        """
        Analisa conteúdo já carregado em memória.
        Útil para integração com o monitor (Patch 4) que já tem o conteúdo.
        """
        t0  = time.monotonic()
        ctx = HeuristicContext(
            path           = path,
            content_sample = content[:CONTENT_SAMPLE_SIZE],
            is_script      = content[:2] == b"#!",
            is_elf         = content[:4] == b"\x7fELF",
        )
        ctx.extension = Path(path).suffix.lower()

        matches, rules_fired = self._evaluate_rules(ctx)
        score, risk          = self._calculate_score(matches)

        return HeuristicResult(
            path            = path,
            score           = score,
            risk_level      = risk,
            matches         = tuple(matches),
            rules_fired     = tuple(rules_fired),
            confidence      = 0.8,   # sem stat/mode info
            analysis_ms     = int((time.monotonic() - t0) * 1000),
            context_summary = {},
        )

    # ------------------------------------------------------------------
    # Construção do contexto
    # ------------------------------------------------------------------

    def _build_context(self, path: str) -> HeuristicContext:
        p = Path(path)

        # Stat básico
        try:
            st        = p.stat()
            file_size = st.st_size
            mode      = st.st_mode
            uid       = st.st_uid
            is_exec   = bool(mode & (stat_mod.S_IXUSR | stat_mod.S_IXGRP | stat_mod.S_IXOTH))
        except OSError:
            file_size = uid = mode = None
            is_exec = False

        # Leitura de conteúdo (limitada a CONTENT_SAMPLE_SIZE)
        content: Optional[bytes] = None
        try:
            with open(path, "rb") as fh:
                content = fh.read(CONTENT_SAMPLE_SIZE)
        except (OSError, PermissionError):
            pass

        is_elf_bin = (content[:4] == b"\x7fELF") if content and len(content) >= 4 else False
        is_sh      = (content[:2] == b"#!")      if content and len(content) >= 2 else False

        # Entropia (só para executáveis — evita custo desnecessário)
        entropy: Optional[float] = None
        if content and (is_exec or is_elf_bin) and len(content) >= 256:
            import math
            freq    = [0] * 256
            for b in content:
                freq[b] += 1
            n       = len(content)
            entropy = -sum((c/n) * math.log2(c/n) for c in freq if c > 0)

        return HeuristicContext(
            path            = path,
            file_size       = file_size,
            entropy         = entropy,
            is_elf          = is_elf_bin,
            is_script       = is_sh,
            is_executable   = is_exec,
            extension       = p.suffix.lower(),
            content_sample  = content,
            uid             = uid,
            mode            = mode,
        )

    # ------------------------------------------------------------------
    # Avaliação de regras
    # ------------------------------------------------------------------

    def _evaluate_rules(
        self, ctx: HeuristicContext
    ) -> tuple[list[RuleMatch], list[str]]:
        matches:     list[RuleMatch] = []
        rules_fired: list[str]       = []

        for rule in self._rules:
            m = rule.match(ctx)
            if m is not None:
                matches.append(m)
                rules_fired.append(rule.rule_id)

        return matches, rules_fired

    # ------------------------------------------------------------------
    # Cálculo de score
    # ------------------------------------------------------------------

    def _calculate_score(
        self, matches: list[RuleMatch]
    ) -> tuple[float, Optional[str]]:
        if not matches:
            return 0.0, None

        # Score ponderado: cada regra disparada contribui com seu peso×10
        # Cap em 100. Não dividimos por total — cada regra é independente.
        fired_weight = sum(
            RULES_BY_ID[m.rule_id].weight
            for m in matches
            if m.rule_id in RULES_BY_ID
        )

        # Escala: peso 10 = 20 pontos; 5 regras críticas (50 pts) = crítico
        raw_score = min(fired_weight * 2.0, 100.0)

        # Sensibilidade ajusta os thresholds
        sensitivity_adj = {
            "low":     1.3,   # precisa de mais evidências
            "medium":  1.0,
            "high":    0.8,   # mais sensível → score aparece maior
            "paranoid":0.6,
        }.get(self._sensitivity, 1.0)

        score = min(raw_score / sensitivity_adj, 100.0)

        # Determina risk_level
        risk = None
        for threshold, level in _SCORE_THRESHOLDS:
            if score >= threshold:
                risk = level
                break

        # Piso de severidade: o campo `severity` de cada regra (usado até
        # agora só como metadado de exibição na CLI) precisa valer pra
        # alguma coisa real. Sem isso, uma única regra "crítico" isolada
        # (ex. H006 reverse shell, H011 fork bomb, H015 fileless) sempre
        # ficava diluída em "baixo" pela fórmula agregada — peso 10 = só
        # 20 pontos, longe do threshold 80 de "crítico" — mesmo sendo um
        # indicador inequívoco por si só. O piso garante que o risk_level
        # final nunca fique abaixo da maior severidade entre as regras que
        # dispararam, sem alterar o score numérico (ainda útil pra
        # diagnóstico) nem a lógica de combinação de sinais fracos.
        severity_floor = max(
            (RULES_BY_ID[m.rule_id].severity
             for m in matches if m.rule_id in RULES_BY_ID),
            key=lambda s: _SEVERITY_RANK.get(s, 0),
            default=None,
        )
        if _SEVERITY_RANK.get(severity_floor, 0) > _SEVERITY_RANK.get(risk, 0):
            risk = severity_floor

        return score, risk

    def _confidence(self, ctx: HeuristicContext) -> float:
        """
        Proporção de regras que puderam ser avaliadas
        (ctx tinha as informações necessárias).
        """
        evaluable = sum(
            1 for r in self._rules
            if not (
                # Regras de conteúdo requerem content_sample
                "script" in r.tags and ctx.content_sample is None
            )
        )
        return min(evaluable / max(len(self._rules), 1), 1.0)

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def _log_result(self, result: HeuristicResult) -> None:
        if not self._log:
            return
        try:
            level = LogLevel.CRITICAL if result.is_critical else LogLevel.WARNING
            rules = ", ".join(result.rules_fired[:5])
            msg   = (
                f"[HEURISTIC] {result.path} — score={result.score:.1f} "
                f"risco={result.risk_level} regras=[{rules}]"
            )
            self._log.get_source("heuristics").event(
                EventType.THREAT_DETECTED, msg,
                level=level, file_path=result.path,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _ctx_summary(ctx: HeuristicContext) -> dict:
        return {
            "is_elf":       ctx.is_elf,
            "is_script":    ctx.is_script,
            "is_executable":ctx.is_executable,
            "entropy":      round(ctx.entropy, 3) if ctx.entropy else None,
            "file_size":    ctx.file_size,
            "extension":    ctx.extension,
        }

    @staticmethod
    def _empty_result(path: str) -> HeuristicResult:
        return HeuristicResult(
            path=path, score=0.0, risk_level=None,
            matches=(), rules_fired=(), confidence=0.0,
            analysis_ms=0, context_summary={},
        )

    def status(self) -> dict:
        return {
            "enabled":     self._enabled,
            "rules_total": len(ALL_RULES),
            "rules_active":len(self._rules),
            "sensitivity": self._sensitivity,
        }
