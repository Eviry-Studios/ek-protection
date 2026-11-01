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
      * Executável sem arquivo (memfd_create + exec, malware fileless)
      * Programa em dir suspeito rodado via loader dinâmico (ld.so /tmp/x)
      * Processos com UID 0 inesperados
      * Processos com muitas conexões de rede abertas
      * Shells invocadas por processos não-interativos
      * Minerador na cmdline (pool stratum, carteira, --donate-level...)

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
import re
from typing import Optional

import psutil

from ..heuristics.rules import cmdline_miner_signals
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

# Nome embutido só vale como confiável se o executável real estiver num
# destes diretórios (rodada 2026-10-29). Fora deles é impostor: `xmrig`
# copiado pra ~/bash herdava a dispensa de CPU só pelo nome.
_SYSTEM_EXEC_DIRS = (
    "/usr/bin", "/usr/sbin", "/bin", "/sbin",
    "/usr/lib", "/lib", "/usr/libexec", "/usr/local/bin", "/usr/local/sbin",
)

# Diretórios suspeitos para executáveis
# `proc.exe()` já vem resolvido, então `/proc/self/fd` nunca casava aqui;
# exec a partir de memfd aparece como `/memfd:<nome>` (ver _MEMFD_EXE_PREFIX).
_SUSPICIOUS_EXEC_DIRS = {
    "/tmp", "/dev/shm", "/var/tmp", "/run/user",
}

# Exe de processo carregado via memfd_create + execve(/proc/self/fd/N).
# O kernel mostra `/memfd:<nome>` (com ` (deleted)` em kernels antigos).
_MEMFD_EXE_PREFIX = "/memfd:"

# Loader dinâmico chamado direto (`/lib64/ld-linux-x86-64.so.2 /tmp/x`,
# rodada 2026-11-01): o exe é o loader, em dir de sistema, e o programa de
# verdade só aparece na cmdline. Também roda arquivo sem bit +x, o que fura
# `/tmp` montado com noexec.
_LOADER_NAME_RE = re.compile(r"^(ld-linux[\w.-]*\.so(\.\d+)*|ld-musl-[\w.-]+\.so(\.\d+)*|ld\.so(\.\d+)*)$")
# Opções do ld.so que consomem o argumento seguinte.
_LOADER_OPTS_WITH_ARG = {
    "--library-path", "--preload", "--audit", "--argv0", "--inhibit-rpath",
    "--glibc-hwcaps-prefix", "--glibc-hwcaps-mask",
}
# Só inspecionam o binário, não executam (usadas pelo ldd).
_LOADER_NO_EXEC_OPTS = {"--list", "--verify", "--help", "--version", "--list-tunables", "--list-diagnostics"}
# `ld.so /proc/self/fd/N`: memfd passado direto pro loader.
_PROC_FD_RE = re.compile(r"^/proc/(self|\d+)/fd/\d+$")

# Sinais distintos de minerador na cmdline pra alertar (ver cmdline_miner_signals)
_MINER_MIN_SIGNALS = 2

# Limites para alertas
_CPU_ALERT_PCT    = 80.0   # % de CPU sustentado por 2 ciclos consecutivos
_NET_CONN_ALERT   = 50     # número de conexões abertas


def _in_suspicious_dir(path: str) -> Optional[str]:
    """Dir suspeito que contém `path` (com fronteira: `/tmpfoo/x` não é `/tmp`)."""
    for d in _SUSPICIOUS_EXEC_DIRS:
        if path.startswith(d + "/"):
            return d
    return None


def _loader_target(exe: Optional[str], cmdline: list[str]) -> Optional[str]:
    """Programa executado quando o processo é o loader dinâmico chamado
    direto. None se o exe não é loader, se só inspeciona (--list/--verify)
    ou se não há programa na cmdline."""
    if not exe or not _LOADER_NAME_RE.match(os.path.basename(exe)):
        return None
    args = iter(cmdline[1:])
    for arg in args:
        if arg in _LOADER_NO_EXEC_OPTS:
            return None
        if arg in _LOADER_OPTS_WITH_ARG:
            next(args, None)
            continue
        if arg.startswith("--"):
            continue
        return arg
    return None


def _exe_is_system(exe: Optional[str]) -> bool:
    """Exe compatível com nome confiável embutido. None (sem permissão pra
    ler) mantém a confiança, como antes; "" é thread de kernel."""
    if not exe:
        return True
    return any(exe.startswith(d + "/") for d in _SYSTEM_EXEC_DIRS)


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
        # Nomes do usuário (config) seguem confiáveis só pelo nome: escolha
        # explícita dele, pode ser app fora dos dirs de sistema.
        self._user_trusted = set(trusted or ())
        self._trusted  = self._user_trusted | _TRUSTED_PROCESSES
        self._running  = False
        self._snapshot: dict[int, str] = {}   # pid → name
        self._cpu_high: dict[int, int] = {}   # pid → contagem de ciclos com CPU alto
        # pid → (create_time, sinais de minerador): cmdline lida uma vez por processo
        self._miner_cache: dict[int, tuple[float, list[str]]] = {}
        # pid → psutil.Process reaproveitado entre ticks. cpu_percent(None)
        # mede desde a chamada anterior *no mesmo objeto*; num objeto novo a
        # 1ª chamada sempre devolve 0.0 (rodada 2026-10-29).
        self._procs: dict[int, psutil.Process] = {}
        # pid → tipos de motivo já alertados. Sem isso, CPU alta repetia o
        # WARNING a cada tick (~720/h num build de 1h, rodada 2026-10-30).
        self._alerted: dict[int, frozenset[str]] = {}

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
            self._miner_cache.pop(pid, None)
            self._procs.pop(pid, None)
            self._cpu_high.pop(pid, None)
            self._alerted.pop(pid, None)

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
            proc = self._get_proc(pid)
            name = proc.name()
            # Rodada 2026-10-28: o nome (comm) é só o basename do executável,
            # então `cp xmrig /tmp/bash` herdava a confiança e pulava tudo.
            # Nome confiável agora só dispensa as checagens de comportamento
            # (CPU, conexões); executável em dir suspeito e minerador na
            # cmdline valem pra qualquer nome.
            # (tipo, texto): o tipo identifica o motivo pro dedup, o texto
            # carrega o valor medido (CPU %, nº de conexões).
            reasons: list[tuple[str, str]] = []

            # Executável em diretório suspeito
            try:
                exe = proc.exe()
                suspicious_dir = _in_suspicious_dir(exe)
                if suspicious_dir:
                    reasons.append(("exe_dir", f"executável em {suspicious_dir}"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, FileNotFoundError):
                exe = None

            if exe and exe.startswith(_MEMFD_EXE_PREFIX):
                reasons.append(("memfd", f"executável sem arquivo ({exe})"))

            loader_reason = self._loader_reason(proc, exe)
            if loader_reason:
                reasons.append(("loader", loader_reason))

            trusted = name in self._user_trusted or (
                name in self._trusted and _exe_is_system(exe)
            )

            miner = self._miner_signals(proc, pid)
            if len(miner) >= _MINER_MIN_SIGNALS:
                reasons.append(("miner", f"minerador na cmdline ({', '.join(miner)})"))

            if trusted and not reasons:
                self._alerted.pop(pid, None)
                return None

            # Processo sem nome
            if not name or name.strip() == "":
                reasons.append(("no_name", "processo sem nome"))

            # CPU alta sustentada
            cpu = None
            try:
                cpu = proc.cpu_percent(interval=None)
                if cpu > _CPU_ALERT_PCT:
                    self._cpu_high[pid] = self._cpu_high.get(pid, 0) + 1
                    if self._cpu_high[pid] >= 2:
                        reasons.append(("cpu", f"CPU alta sustentada ({cpu:.0f}%)"))
                else:
                    self._cpu_high.pop(pid, None)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                pass

            # Muitas conexões de rede abertas
            try:
                conns = proc.net_connections()
                if len(conns) > _NET_CONN_ALERT:
                    reasons.append(("net", f"{len(conns)} conexões de rede abertas"))
            except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                pass

            if not reasons:
                self._alerted.pop(pid, None)
                return None

            # Dedup: alerta só quando aparece um tipo de motivo que não estava
            # no alerta anterior. Motivo que some e volta alerta de novo.
            kinds = frozenset(k for k, _ in reasons)
            previous = self._alerted.get(pid, frozenset())
            self._alerted[pid] = kinds
            if kinds <= previous:
                return None

            # Coleta metadados completos para o evento
            try:
                cmdline  = proc.cmdline()
                ppid     = proc.ppid()
                username = proc.username()
                mem_pct  = proc.memory_percent()
                # Não chama cpu_percent de novo: mediria só os µs desde a
                # chamada acima e zeraria a base do próximo tick.
                cpu_pct  = cpu
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
                reason   = "; ".join(text for _, text in reasons),
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

    def _get_proc(self, pid: int) -> psutil.Process:
        """psutil.Process do pid, reaproveitado entre ticks. PID reusado
        (create_time diferente) ganha objeto novo e zera a contagem de CPU."""
        proc = self._procs.get(pid)
        if proc is not None:
            try:
                if proc.is_running():   # compara create_time internamente
                    return proc
            except psutil.Error:
                pass
            self._cpu_high.pop(pid, None)
            self._alerted.pop(pid, None)
        proc = psutil.Process(pid)
        self._procs[pid] = proc
        return proc

    def _loader_reason(self, proc: psutil.Process, exe: Optional[str]) -> Optional[str]:
        # Checa o nome antes de ler a cmdline: só o loader paga a leitura de
        # /proc/<pid>/cmdline (o resto usa o cache de _miner_signals).
        if not exe or not _LOADER_NAME_RE.match(os.path.basename(exe)):
            return None
        target = _loader_target(exe, self._safe_cmdline(proc))
        if not target:
            return None
        loader = os.path.basename(exe)
        if _PROC_FD_RE.match(target):
            return f"loader {loader} executando descritor ({target})"
        if not target.startswith("/"):
            try:
                target = os.path.join(proc.cwd(), target)
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                return None
        target = os.path.normpath(target)
        suspicious_dir = _in_suspicious_dir(target)
        if suspicious_dir:
            return f"loader {loader} executando programa em {suspicious_dir} ({target})"
        return None

    def _miner_signals(self, proc: psutil.Process, pid: int) -> list[str]:
        """Sinais de minerador na cmdline, com cache por (pid, create_time)
        pra não reler /proc/<pid>/cmdline de todo processo a cada tick."""
        try:
            ctime = proc.create_time()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            return []
        cached = self._miner_cache.get(pid)
        if cached is not None and cached[0] == ctime:
            return cached[1]
        signals = cmdline_miner_signals(self._safe_cmdline(proc))
        self._miner_cache[pid] = (ctime, signals)
        return signals

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
            "alerted_pids":  len(self._alerted),
        }
