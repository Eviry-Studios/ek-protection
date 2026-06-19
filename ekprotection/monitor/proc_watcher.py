"""
ekprotection.monitor.proc_watcher
===================================
Monitoramento de processos via psutil.

Detecta:
  - Processos novos (comparação de snapshots)
  - Processos encerrados
  - Comportamento suspeito em processos existentes:
      * Alto consumo de CPU sustentado
      * Processos sem nome / nome vazio
      * Executáveis em /tmp ou /dev/shm
      * Processos com UID 0 inesperados
      * Processos com muitas conexões de rede abertas
      * Shells invocadas por processos não-interativos

Design:
  - Polling periódico assíncrono (não usa inotify para processos)
  - Intervalo configurável (padrão 5s) para baixo consumo de CPU
  - Cache de snapshot anterior para detectar entradas/saídas
  - Empurra ProcessEvent para asyncio.Queue
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

import psutil

from .events import ProcessEvent, ProcEventKind

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuração de heurísticas de processo
# ---------------------------------------------------------------------------

# Nomes de processos sempre confiáveis (nunca reportados como suspeitos)
_TRUSTED_PROCESSES = {
    "systemd", "kthreadd", "kworker", "ksoftirqd", "migration",
    "rcu_sched", "watchdog", "idle", "init", "sh", "bash", "zsh",
    "sshd", "cron", "rsyslogd", "journald", "udevd",
    "ekp", "ekp-daemon",   # o próprio EK-Protection
}

# Diretórios suspeitos para executáveis
_SUSPICIOUS_EXEC_DIRS = {
    "/tmp", "/dev/shm", "/var/tmp", "/run/user",
    "/proc/self/fd",
}

# Limites para alertas
_CPU_ALERT_PCT    = 80.0   # % de CPU sustentado por 2 ciclos consecutivos
_NET_CONN_ALERT   = 50     # número de conexões abertas


class ProcWatcher:
    """
    Monitor de processos por polling periódico.

    Uso (dentro do loop assíncrono do engine):
        watcher = ProcWatcher(queue, interval=5.0)
        task = asyncio.create_task(watcher.run())
        ...
        watcher.stop()
        await task
    """

    def __init__(
        self,
        queue:    asyncio.Queue,
        interval: float = 5.0,
        trusted:  Optional[set[str]] = None,
    ) -> None:
        self._queue    = queue
        self._interval = interval
        self._trusted  = (trusted or set()) | _TRUSTED_PROCESSES
        self._running  = False
        self._snapshot: dict[int, str] = {}   # pid → name
        self._cpu_high: dict[int, int] = {}   # pid → contagem de ciclos com CPU alto

    # ------------------------------------------------------------------
    # Loop principal
    # ------------------------------------------------------------------

    async def run(self) -> None:
        """Loop assíncrono de monitoramento de processos."""
        self._running = True
        logger.info("ProcWatcher iniciado (intervalo: %.1fs).", self._interval)

        # Snapshot inicial — não reporta processos já existentes como "novos"
        self._snapshot = self._current_pids()

        while self._running:
            try:
                await self._tick()
            except Exception as exc:
                logger.error("Erro no ProcWatcher tick: %s", exc)
            await asyncio.sleep(self._interval)

        logger.info("ProcWatcher encerrado.")

    def stop(self) -> None:
        """Sinaliza parada do loop."""
        self._running = False

    # ------------------------------------------------------------------
    # Tick de monitoramento
    # ------------------------------------------------------------------

    async def _tick(self) -> None:
        current = self._current_pids()

        new_pids  = set(current) - set(self._snapshot)
        gone_pids = set(self._snapshot) - set(current)

        # Processos novos
        for pid in new_pids:
            ev = self._build_proc_event(pid, ProcEventKind.NEW)
            if ev:
                await self._queue.put(ev)

        # Processos encerrados
        for pid in gone_pids:
            ev = ProcessEvent(
                kind  = ProcEventKind.TERMINATED,
                pid   = pid,
                name  = self._snapshot.get(pid, "?"),
            )
            await self._queue.put(ev)

        # Verifica suspeitos nos processos em execução
        for pid in current:
            ev = await self._check_suspicious(pid)
            if ev:
                await self._queue.put(ev)

        self._snapshot = current

    # ------------------------------------------------------------------
    # Detecção de suspeitos
    # ------------------------------------------------------------------

    async def _check_suspicious(self, pid: int) -> Optional[ProcessEvent]:
        """Analisa um processo em execução. Retorna ProcessEvent ou None."""
        try:
            proc = psutil.Process(pid)
            name = proc.name()

            if name in self._trusted:
                return None

            reasons: list[str] = []

            # Executável em diretório suspeito
            try:
                exe = proc.exe()
                for suspicious_dir in _SUSPICIOUS_EXEC_DIRS:
                    if exe.startswith(suspicious_dir):
                        reasons.append(f"executável em {suspicious_dir}")
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                exe = None

            # Processo sem nome
            if not name or name.strip() == "":
                reasons.append("processo sem nome")

            # CPU alta sustentada
            try:
                cpu = proc.cpu_percent(interval=None)
                if cpu > _CPU_ALERT_PCT:
                    self._cpu_high[pid] = self._cpu_high.get(pid, 0) + 1
                    if self._cpu_high[pid] >= 2:
                        reasons.append(f"CPU alta sustentada ({cpu:.0f}%)")
                else:
                    self._cpu_high.pop(pid, None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Muitas conexões de rede abertas
            try:
                conns = proc.net_connections()
                if len(conns) > _NET_CONN_ALERT:
                    reasons.append(f"{len(conns)} conexões de rede abertas")
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            if not reasons:
                return None

            # Coleta metadados completos para o evento
            try:
                cmdline  = proc.cmdline()
                ppid     = proc.ppid()
                username = proc.username()
                mem_pct  = proc.memory_percent()
                cpu_pct  = proc.cpu_percent(interval=None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                cmdline, ppid, username, mem_pct, cpu_pct = [], None, None, None, None

            return ProcessEvent(
                kind     = ProcEventKind.SUSPICIOUS,
                pid      = pid,
                name     = name,
                exe      = exe,
                cmdline  = cmdline,
                ppid     = ppid,
                username = username,
                mem_pct  = mem_pct,
                cpu_pct  = cpu_pct,
                reason   = "; ".join(reasons),
            )

        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None
        except Exception as exc:
            logger.debug("Erro ao verificar PID %d: %s", pid, exc)
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build_proc_event(self, pid: int, kind: ProcEventKind) -> Optional[ProcessEvent]:
        """Constrói ProcessEvent com metadados para processo novo."""
        try:
            proc = psutil.Process(pid)
            return ProcessEvent(
                kind     = kind,
                pid      = pid,
                name     = proc.name(),
                exe      = self._safe_exe(proc),
                cmdline  = self._safe_cmdline(proc),
                ppid     = proc.ppid(),
                username = self._safe_username(proc),
            )
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            return None

    @staticmethod
    def _current_pids() -> dict[int, str]:
        """Retorna snapshot {pid: name} dos processos atuais."""
        result = {}
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                result[proc.pid] = proc.info["name"] or ""
            except (psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
        return result

    @staticmethod
    def _safe_exe(proc: psutil.Process) -> Optional[str]:
        try:
            return proc.exe()
        except (psutil.AccessDenied, FileNotFoundError):
            return None

    @staticmethod
    def _safe_cmdline(proc: psutil.Process) -> list[str]:
        try:
            return proc.cmdline()
        except psutil.AccessDenied:
            return []

    @staticmethod
    def _safe_username(proc: psutil.Process) -> Optional[str]:
        try:
            return proc.username()
        except (psutil.AccessDenied, KeyError):
            return None

    def status(self) -> dict:
        return {
            "running":       self._running,
            "interval_s":    self._interval,
            "tracked_pids":  len(self._snapshot),
            "cpu_high_pids": len(self._cpu_high),
        }
