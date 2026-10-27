#!/usr/bin/env python3
"""
CyberLab OS <-> chat.py Partner Bridge Daemon (cyberlab-partner v1.0)

Funciona exatamente como um conector de Telegram para o seu runtime externo em Python (`chat.py`),
mas em vez de fazer polling na API do Telegram, expõe um endpoint HTTP local autenticado via
HMAC-SHA256 (127.0.0.1:8788/cyberlab/partner) compatível com o PartnerBridge do CyberLab OS.

Modos de invocação do seu `chat.py`:
  1. --mode arg    -> executa: python3 /caminho/chat.py "<prompt>"
  2. --mode stdin  -> envia <prompt> na entrada padrão (stdin) de: python3 /caminho/chat.py
  3. --mode import -> importa uma função Python diretamente (--callable /caminho/chat.py:responder)

Uso:
  export CYBERLAB_PARTNER_SECRET="troque-por-um-segredo-forte-com-32-caracteres"
  python3 integrations/partners/chat_py_bridge.py \
    --script /caminho/para/chat.py \
    --mode arg \
    --partner-id chat-py-agent \
    --host 127.0.0.1 \
    --port 8788
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable

MAX_ENVELOPE_BYTES = 256 * 1024  # 256 KiB


def canonical_json(value: Any) -> str:
    """Serializa JSON com chaves ordenadas e sem espaços, idêntico ao canonicalJson() do CyberLab OS."""
    if value is None or isinstance(value, (bool, int, float, str)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if isinstance(value, list):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        keys = sorted(k for k, v in value.items() if v is not None)
        return "{" + ",".join(
            f"{json.dumps(k, ensure_ascii=False)}:{canonical_json(value[k])}" for k in keys
        ) + "}"
    return json.dumps(str(value), ensure_ascii=False)


def compute_envelope_hmac(envelope: dict[str, Any], secret: str) -> str:
    payload_no_sig = {k: v for k, v in envelope.items() if k != "signature"}
    canonical = canonical_json(payload_no_sig)
    return hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def build_prompt_from_task(task: dict[str, Any]) -> str:
    ctx = task.get("contextBundle") or {}
    evidence_ids = ", ".join(ctx.get("evidenceIds") or []) or "nenhuma"
    redacted_text = ctx.get("text") or ""
    allowed = ", ".join(task.get("allowedActions") or []) or "analyze.evidence"
    prohibited = ", ".join(task.get("prohibitedActions") or []) or "execução direta de comandos"

    parts = [
        "[CyberLab OS — Tarefa Delegada ao Agente Parceiro]",
        f"Task ID: {task.get('taskId', 'unknown')}",
        f"Projeto: {task.get('projectId', 'unknown')}",
        f"Objetivo: {task.get('objective', '')}",
        f"Ações permitidas: {allowed}",
        f"Ações proibidas: {prohibited}",
        f"IDs de Evidência referenciados: {evidence_ids}",
    ]
    if redacted_text:
        parts.append(f"Contexto Técnico (já redigido pelo CyberLab OS):\n{redacted_text}")

    parts.append(
        "Se possível, responda em JSON estruturado no formato:\n"
        '{"summary":"...","findings":[{"title":"...","description":"...","evidenceRefs":[],"confidence":0.7}],"limitations":["..."]}\n'
        "Caso responda em texto livre, o conector encapsulará o texto como resumo analítico não revisado."
    )
    return "\n\n".join(parts)


def load_python_callable(spec: str) -> Callable[[str], Any]:
    if ":" not in spec:
        raise ValueError("--callable deve estar no formato /caminho/para/chat.py:nome_da_funcao")
    file_part, func_name = spec.rsplit(":", 1)
    script_path = Path(file_part).expanduser().resolve()
    if not script_path.is_file():
        raise FileNotFoundError(f"Arquivo Python não encontrado: {script_path}")

    script_dir = str(script_path.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    mod_spec = importlib.util.spec_from_file_location("cyberlab_external_chat_py", script_path)
    if mod_spec is None or mod_spec.loader is None:
        raise RuntimeError(f"Não foi possível carregar módulo de {script_path}")
    module = importlib.util.module_from_spec(mod_spec)
    mod_spec.loader.exec_module(module)
    fn = getattr(module, func_name, None)
    if not callable(fn):
        raise AttributeError(f" Função '{func_name}' não encontrada ou não invocável em {script_path}")
    return fn


class ChatPyRunner:
    def __init__(
        self,
        mode: str,
        script_path: str | None,
        callable_spec: str | None,
        python_bin: str,
        timeout_sec: int,
    ) -> None:
        self.mode = mode
        self.script_path = str(Path(script_path).expanduser().resolve()) if script_path else None
        self.python_bin = python_bin
        self.timeout_sec = timeout_sec
        self._callable = load_python_callable(callable_spec) if mode == "import" and callable_spec else None

        if mode in ("arg", "stdin"):
            if not self.script_path or not Path(self.script_path).is_file():
                raise FileNotFoundError(f"Script chat.py não encontrado: {self.script_path}")
        elif mode == "import" and self._callable is None:
            raise ValueError("Modo 'import' exige --callable /caminho/para/chat.py:funcao")

    def invoke(self, prompt: str) -> str:
        if self.mode == "import" and self._callable is not None:
            result = self._callable(prompt)
            if isinstance(result, (dict, list)):
                return json.dumps(result, ensure_ascii=False)
            return str(result)

        assert self.script_path is not None
        cwd = str(Path(self.script_path).parent)
        if self.mode == "arg":
            proc = subprocess.run(
                [self.python_bin, self.script_path, prompt],
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )
        else:
            proc = subprocess.run(
                [self.python_bin, self.script_path],
                cwd=cwd,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )

        if proc.returncode != 0:
            stderr_preview = (proc.stderr or "").strip()[:500]
            raise RuntimeError(f"chat.py retornou código {proc.returncode}: {stderr_preview}")
        return (proc.stdout or "").strip()


def normalize_chat_output(task_id: str, raw_output: str) -> dict[str, Any]:
    limitations = [
        "Resposta originada de runtime externo via chat_py_bridge.py; requer validação humana contra evidências brutas."
    ]
    try:
        parsed = json.loads(raw_output)
        if isinstance(parsed, dict):
            raw_findings = parsed.get("findings") if isinstance(parsed.get("findings"), list) else []
            clean_findings = []
            for item in raw_findings:
                if isinstance(item, dict) and item.get("title") and item.get("description"):
                    clean_entry: dict[str, Any] = {
                        "title": str(item["title"])[:200],
                        "description": str(item["description"])[:8000],
                        "evidenceRefs": [
                            str(r) for r in (item.get("evidenceRefs") or []) if isinstance(r, str)
                        ],
                    }
                    if isinstance(item.get("confidence"), (int, float)):
                        clean_entry["confidence"] = max(0.0, min(1.0, float(item["confidence"])))
                    clean_findings.append(clean_entry)

            extra_lims = [str(x) for x in (parsed.get("limitations") or []) if isinstance(x, str)]
            return {
                "taskId": task_id,
                "status": parsed.get("status")
                if parsed.get("status") in ("completed", "partial", "failed", "rejected")
                else "completed",
                "summary": str(parsed.get("summary") or "Análise concluída pelo chat.py")[:16000],
                "findings": clean_findings,
                "limitations": extra_lims + limitations,
                "artifactRefs": [],
            }
    except Exception:
        pass

    return {
        "taskId": task_id,
        "status": "completed",
        "summary": (raw_output or "Resposta vazia do chat.py")[:16000],
        "findings": [],
        "limitations": [
            "chat.py retornou texto livre (não-JSON); convertido em resumo não revisado sem privilégio de execução."
        ]
        + limitations,
        "artifactRefs": [],
    }


def make_handler(partner_id: str, secret: str, runner: ChatPyRunner):
    class PartnerBridgeHandler(BaseHTTPRequestHandler):
        def _send_json(self, status_code: int, payload: Any) -> None:
            raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status_code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._send_json(200, {"ok": True, "partnerId": partner_id, "protocol": "cyberlab-partner/1.0"})
                return
            self._send_json(404, {"error": "Not found"})

        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/cyberlab/partner":
                self._send_json(404, {"error": "Unknown endpoint; use /cyberlab/partner"})
                return

            content_len = int(self.headers.get("Content-Length", "0"))
            if content_len <= 0 or content_len > MAX_ENVELOPE_BYTES:
                self._send_json(413, {"error": "Invalid or oversized PartnerEnvelope"})
                return

            raw_body = self.rfile.read(content_len)
            try:
                inbound = json.loads(raw_body.decode("utf-8"))
            except Exception:
                self._send_json(400, {"error": "Invalid JSON"})
                return

            if (
                not isinstance(inbound, dict)
                or inbound.get("protocol") != "cyberlab-partner"
                or inbound.get("protocolVersion") != "1.0"
            ):
                self._send_json(400, {"error": "Unsupported protocol or version"})
                return

            provided_sig = str(inbound.get("signature") or "")
            expected_sig = compute_envelope_hmac(inbound, secret)
            if not hmac.compare_digest(provided_sig, expected_sig):
                self._send_json(401, {"error": "HMAC-SHA256 signature verification failed"})
                return

            msg_type = inbound.get("type")
            sender_id = (inbound.get("sender") or {}).get("id", "cyberlab-core")
            correlation_id = inbound.get("correlationId") or f"corr-{uuid.uuid4()}"

            if msg_type == "task.cancel":
                ack: dict[str, Any] = {
                    "protocol": "cyberlab-partner",
                    "protocolVersion": "1.0",
                    "messageId": f"pmsg-{uuid.uuid4()}",
                    "correlationId": correlation_id,
                    "sentAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    "sender": {"id": partner_id, "type": "partner"},
                    "recipient": {"id": sender_id},
                    "type": "task.accepted",
                    "payload": {"cancelled": True},
                }
                ack["signature"] = compute_envelope_hmac(ack, secret)
                self._send_json(200, [ack])
                return

            if msg_type != "task.submit":
                self._send_json(400, {"error": f"Unsupported inbound message type: {msg_type}"})
                return

            task = inbound.get("payload") or {}
            task_id = str(task.get("taskId") or f"task-{uuid.uuid4()}")
            prompt = build_prompt_from_task(task)

            try:
                raw_reply = runner.invoke(prompt)
                result_payload = normalize_chat_output(task_id, raw_reply)
                out_type = "task.result"
            except Exception as exc:
                result_payload = {
                    "taskId": task_id,
                    "status": "failed",
                    "summary": f"Falha ao executar chat.py: {exc}",
                    "findings": [],
                    "limitations": ["Execução de chat.py falhou ou excedeu o timeout configurado."],
                    "artifactRefs": [],
                }
                out_type = "task.result"

            outbound: dict[str, Any] = {
                "protocol": "cyberlab-partner",
                "protocolVersion": "1.0",
                "messageId": f"pmsg-{uuid.uuid4()}",
                "correlationId": correlation_id,
                "sentAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "sender": {"id": partner_id, "type": "partner"},
                "recipient": {"id": sender_id},
                "type": out_type,
                "payload": result_payload,
            }
            outbound["signature"] = compute_envelope_hmac(outbound, secret)
            self._send_json(200, [outbound])

        def log_message(self, fmt: str, *args: Any) -> None:
            sys.stderr.write(f"[chat_py_bridge] {self.address_string()} - {fmt % args}\n")

    return PartnerBridgeHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Conector CyberLab OS <-> chat.py (HMAC-SHA256)")
    parser.add_argument("--partner-id", default=os.environ.get("CYBERLAB_PARTNER_ID", "chat-py-agent"))
    parser.add_argument("--host", default=os.environ.get("CYBERLAB_BRIDGE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CYBERLAB_BRIDGE_PORT", "8788")))
    parser.add_argument("--mode", choices=["arg", "stdin", "import"], default="arg")
    parser.add_argument("--script", help="Caminho para o seu chat.py (usado em --mode arg ou --mode stdin)")
    parser.add_argument("--callable", help="Ex.: /caminho/chat.py:responder (usado em --mode import)")
    parser.add_argument("--python-bin", default=sys.executable, help="Interpretador Python para rodar chat.py")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout em segundos por chamada ao chat.py")
    args = parser.parse_args()

    secret = os.environ.get("CYBERLAB_PARTNER_SECRET", "")
    if len(secret) < 16:
        sys.stderr.write(
            "ERRO: Defina a variável de ambiente CYBERLAB_PARTNER_SECRET com pelo menos 16 caracteres.\n"
        )
        sys.exit(1)

    runner = ChatPyRunner(
        mode=args.mode,
        script_path=args.script,
        callable_spec=args.callable,
        python_bin=args.python_bin,
        timeout_sec=args.timeout,
    )

    server = ThreadingHTTPServer((args.host, args.port), make_handler(args.partner_id, secret, runner))
    sys.stderr.write(
        f"[chat_py_bridge] Ativo em http://{args.host}:{args.port}/cyberlab/partner "
        f"(partnerId={args.partner_id}, mode={args.mode})\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[chat_py_bridge] Encerrando ponte...\n")
        server.server_close()


if __name__ == "__main__":
    main()
