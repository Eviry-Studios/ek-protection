"""
ekprotection.daemon
====================
Daemon do EK-Protection com Unix socket IPC.

Funcionalidades (Patch 9):
  - Unix socket IPC para comunicação CLI ↔ daemon em tempo real
  - Protocolo JSON newline-delimited sobre socket
  - Comandos suportados: status, stop, scan_file, update
  - PID file para controle de instância única
  - Suporte a systemd notify (sd_notify) se disponível
  - Loop assíncrono completo com todos os subsistemas
  - Shutdown limpo via SIGTERM/SIGINT

Protocolo IPC (linha por mensagem):
  Request:  {"cmd": "status"}\n
  Response: {"ok": true, "data": {...}}\n

  Request:  {"cmd": "scan_file", "path": "/tmp/x.sh"}\n
  Response: {"ok": true, "data": {"verdict": "clean", ...}}\n

  Request:  {"cmd": "stop"}\n
  Response: {"ok": true, "data": "stopping"}\n
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing  import Any, Optional

from ekprotection.config.manager import ConfigManager
from ekprotection.core.engine    import EKEngine, EngineState

logger = logging.getLogger(__name__)

# Tamanho máximo de mensagem IPC (4MB)
_MAX_MSG_SIZE = 4 * 1024 * 1024


# ---------------------------------------------------------------------------
# Protocolo IPC
# ---------------------------------------------------------------------------

def _ok(data: Any) -> bytes:
    return (json.dumps({"ok": True,  "data": data}, ensure_ascii=False) + "\n").encode()


def _err(msg: str) -> bytes:
    return (json.dumps({"ok": False, "error": msg}, ensure_ascii=False) + "\n").encode()


# ---------------------------------------------------------------------------
# Servidor IPC
# ---------------------------------------------------------------------------

class IPCServer:
    """
    Servidor Unix socket para comunicação CLI ↔ daemon.

    Cada conexão é um par request/response (protocolo simples sem estado).
    """

    def __init__(
        self,
        socket_path: str,
        engine:      EKEngine,
    ) -> None:
        self._socket_path = socket_path
        self._engine      = engine
        self._server:     Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        sock = Path(self._socket_path)
        sock.parent.mkdir(parents=True, exist_ok=True)
        sock.unlink(missing_ok=True)   # remove socket anterior se existir

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self._socket_path
        )
        # Permissões do socket: root (dono) + grupo ek-protection podem
        # ler/escrever. Isso permite que usuários no grupo "ek-protection"
        # rodem `ekp status`, `ekp scan file`, etc. SEM precisar de sudo,
        # enquanto root continua controlando start/stop/auth/quarantine.
        try:
            os.chmod(self._socket_path, 0o660)
        except OSError:
            pass

        try:
            import grp
            ekp_group = grp.getgrnam("ek-protection")
            os.chown(self._socket_path, 0, ekp_group.gr_gid)
            logger.debug("Socket pertence ao grupo 'ek-protection' (gid=%d).", ekp_group.gr_gid)
        except (KeyError, PermissionError, OSError):
            # Grupo não existe ainda (ex: rodando fora do install.sh) —
            # o socket fica acessível apenas por root. Não é fatal.
            logger.debug(
                "Grupo 'ek-protection' não encontrado; socket restrito a root. "
                "Crie o grupo com: sudo groupadd ek-protection && "
                "sudo usermod -aG ek-protection <seu_usuario>"
            )

        logger.info("IPC socket aberto: %s", self._socket_path)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        Path(self._socket_path).unlink(missing_ok=True)
        logger.info("IPC socket fechado.")

    # ------------------------------------------------------------------
    # Handler de conexão
    # ------------------------------------------------------------------

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            raw = await asyncio.wait_for(
                reader.readline(), timeout=10.0
            )
            if not raw:
                return

            try:
                request = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError:
                writer.write(_err("JSON inválido"))
                await writer.drain()
                return

            response = await self._dispatch(request)
            writer.write(response)
            await writer.drain()

        except asyncio.TimeoutError:
            writer.write(_err("timeout"))
        except Exception as exc:
            logger.debug("Erro IPC: %s", exc)
            try:
                writer.write(_err(str(exc)))
                await writer.drain()
            except Exception:
                pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Dispatcher de comandos
    # ------------------------------------------------------------------

    async def _dispatch(self, req: dict) -> bytes:
        cmd = req.get("cmd", "")

        if cmd == "status":
            return _ok(self._engine.status())

        if cmd == "ping":
            return _ok("pong")

        if cmd == "stop":
            asyncio.create_task(self._delayed_stop())
            return _ok("stopping")

        if cmd == "scan_file":
            return await self._cmd_scan_file(req)

        if cmd == "update":
            return await self._cmd_update(req)

        if cmd == "quarantine_list":
            return self._cmd_quarantine_list()

        if cmd == "log_tail":
            return self._cmd_log_tail(req)

        if cmd == "log_search":
            return self._cmd_log_search(req)

        return _err(f"Comando desconhecido: {cmd}")

    # ------------------------------------------------------------------
    # Comandos individuais
    # ------------------------------------------------------------------

    async def _cmd_scan_file(self, req: dict) -> bytes:
        path = req.get("path", "")
        if not path:
            return _err("Campo 'path' obrigatório.")
        scanner = self._engine.get_subsystem("scanner")
        if not scanner:
            return _err("Scanner não disponível.")
        loop   = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, scanner.scan_file, path)
        return _ok(result.to_dict())

    async def _cmd_update(self, req: dict) -> bytes:
        updater = self._engine.get_subsystem("updater")
        if not updater:
            return _err("Updater não disponível.")
        force  = req.get("force", False)
        loop   = asyncio.get_running_loop()
        result = await loop.run_in_executor(None, updater.update_now, force)
        if result is None:
            return _err("Atualização falhou. Verifique os logs.")
        return _ok({
            "updated":        result.updated,
            "version_before": result.version_before,
            "version_after":  result.version_after,
            "added":          result.added,
            "message":        result.message,
        })

    def _cmd_quarantine_list(self) -> bytes:
        quar = self._engine.quarantine
        if not quar:
            return _err("Quarentena não disponível.")
        entries = quar.list_active()
        return _ok([e.to_dict() for e in entries])

    def _cmd_log_tail(self, req: dict) -> bytes:
        logs = self._engine.logs
        if not logs:
            return _err("Logs não disponíveis.")
        from ekprotection.logs.models import QueryFilter
        n       = min(req.get("n", 20), 200)
        entries = logs.query(QueryFilter(limit=n, order_desc=True))
        return _ok([e.to_dict() for e in entries])

    def _cmd_log_search(self, req: dict) -> bytes:
        logs = self._engine.logs
        if not logs:
            return _err("Logs não disponíveis.")
        from ekprotection.logs.models import build_query_filter
        try:
            f = build_query_filter(
                query = req.get("query"),
                level = req.get("level"),
                event = req.get("event"),
                since = req.get("since"),
                until = req.get("until"),
                path  = req.get("path"),
                limit = req.get("limit", 50),
            )
        except ValueError as exc:
            return _err(str(exc))

        total   = logs.count(f)
        entries = logs.query(f)
        return _ok({"entries": [e.to_dict() for e in entries], "total": total})

    async def _delayed_stop(self) -> None:
        await asyncio.sleep(0.1)
        if self._engine._stop_event:
            self._engine._stop_event.set()


# ---------------------------------------------------------------------------
# Cliente IPC (usado pela CLI)
# ---------------------------------------------------------------------------

class IPCClient:
    """
    Cliente leve para comunicação com o daemon via Unix socket.
    Usado pelos comandos CLI para obter dados em tempo real.
    """

    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        self._socket_path = socket_path
        self._timeout     = timeout

    def send(self, cmd: str, **kwargs: Any) -> dict:
        """
        Envia comando e retorna a resposta como dict.
        Lança ConnectionError se o daemon não estiver rodando.
        """
        import socket as _socket

        request = json.dumps({"cmd": cmd, **kwargs}) + "\n"
        sock    = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        sock.settimeout(self._timeout)

        try:
            sock.connect(self._socket_path)
            sock.sendall(request.encode("utf-8"))

            response = b""
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if b"\n" in response:
                    break
        except _socket.timeout:
            raise ConnectionError(f"Timeout ao conectar ao daemon ({self._socket_path}).")
        except FileNotFoundError:
            raise ConnectionError(
                f"Daemon não encontrado em {self._socket_path}. "
                "Execute: sudo ekp start"
            )
        except ConnectionRefusedError:
            raise ConnectionError(
                "Daemon não está respondendo. Tente reiniciar: sudo ekp restart"
            )
        finally:
            sock.close()

        try:
            return json.loads(response.decode("utf-8").strip())
        except json.JSONDecodeError:
            raise ConnectionError(f"Resposta inválida do daemon: {response[:100]}")

    def is_alive(self) -> bool:
        """Verifica se o daemon está rodando."""
        try:
            resp = self.send("ping")
            return resp.get("data") == "pong"
        except (ConnectionError, OSError):
            return False


# ---------------------------------------------------------------------------
# Funções de daemonização
# ---------------------------------------------------------------------------

def _write_pid(pid_file: str) -> None:
    p = Path(pid_file)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(str(os.getpid()))


def _remove_pid(pid_file: str) -> None:
    Path(pid_file).unlink(missing_ok=True)


def _setup_logging(level: str, log_dir: str) -> None:
    import logging.handlers
    numeric = getattr(logging, level.upper(), logging.INFO)

    # Console handler para foreground
    handlers: list[logging.Handler] = [logging.StreamHandler()]

    # Arquivo rotacionado se o diretório existir
    log_path = Path(log_dir) / "daemon.log"
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.handlers.RotatingFileHandler(
            str(log_path), maxBytes=10*1024*1024, backupCount=3
        ))
    except OSError:
        pass

    logging.basicConfig(
        level   = numeric,
        format  = "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt = "%Y-%m-%d %H:%M:%S",
        handlers= handlers,
    )


def _notify_systemd(message: str) -> None:
    """Envia notificação para systemd sd_notify se disponível."""
    notify_socket = os.environ.get("NOTIFY_SOCKET")
    if not notify_socket:
        return
    try:
        import socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
            if notify_socket.startswith("@"):
                notify_socket = "\0" + notify_socket[1:]
            sock.connect(notify_socket)
            sock.sendall(message.encode())
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Loop principal do daemon
# ---------------------------------------------------------------------------

async def _daemon_loop(config: ConfigManager) -> None:
    """Corrotina principal do daemon."""
    engine     = EKEngine(config)
    pid_file   = config.get("daemon.pid_file",    "/run/ek-protection/daemon.pid")
    socket_path= config.get("daemon.socket_path", "/run/ek-protection/daemon.sock")
    log_dir    = config.get("logs.dir",           "/var/log/ek-protection")

    # Resolve EKP_DATA_DIR
    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        socket_path = socket_path.replace("/run/ek-protection", data_dir + "/run")
        pid_file    = pid_file.replace("/run/ek-protection",    data_dir + "/run")
        log_dir     = log_dir.replace("/var/log/ek-protection", data_dir + "/log")

    _write_pid(pid_file)

    ipc = IPCServer(socket_path, engine)

    try:
        await engine.start()
        await ipc.start()

        # Registra updater como subsistema
        from ekprotection.updater.manager import UpdateManager
        sig_db  = engine.get_subsystem("sig_db")
        updater = UpdateManager(config, sig_db=sig_db, log_manager=engine.logs)
        updater.initialize()
        engine.register("updater", updater)

        # Notifica systemd que estamos prontos
        _notify_systemd("READY=1\nSTATUS=EK-Protection ativo\n")
        logger.info("Daemon pronto. PID=%d, Socket=%s", os.getpid(), socket_path)

        # Loop de atualização automática como task
        if config.get("signatures.auto_update", True):
            asyncio.create_task(updater.run_loop(), name="ekp-updater")

        # Aguarda sinal de parada
        await engine.wait()

    finally:
        _notify_systemd("STOPPING=1\n")
        await ipc.stop()
        await engine.stop()
        _remove_pid(pid_file)
        logger.info("Daemon encerrado.")


def run_daemon(config_path: str | None = None) -> None:
    """Entry point do daemon (registrado em pyproject.toml como ekp-daemon)."""
    cfg = ConfigManager(config_path)
    cfg.load()

    log_level = cfg.get("daemon.log_level", "INFO")
    log_dir   = cfg.get("logs.dir", "/var/log/ek-protection")

    data_dir = os.environ.get("EKP_DATA_DIR", "")
    if data_dir:
        log_dir = log_dir.replace("/var/log/ek-protection", data_dir + "/log")

    _setup_logging(log_level, log_dir)
    logger.info("Iniciando EK-Protection Daemon v0.9.0")

    try:
        asyncio.run(_daemon_loop(cfg))
    except KeyboardInterrupt:
        logger.info("Daemon interrompido via Ctrl+C.")
    except Exception as exc:
        logger.critical("Erro fatal no daemon: %s", exc, exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    run_daemon()
