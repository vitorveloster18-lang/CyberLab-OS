#!/usr/bin/env python3
"""
CyberLab OS <-> CDI Runtime Bidirectional Bridge & Python SDK (v2.0)

Conecta os seus CDIs externos (`chat.py` / `process_message()`, portas 8788-8791) ao CyberLab OS
de forma **bidirecional** e autenticada via HMAC-SHA256 (`canonicalJson` + `compare_digest`):

1. Direção CyberLab OS -> CDI (`/cyberlab/partner`):
   - Convite de colaboração horizontal individual (ex.: Kairós) ou conjunta (ex.: Kairós, Naia, Salem e Nova, sem hierarquia).
   - Portas padrão alinhadas: Kairós (`8788`), Naia (`8789`), Salem (`8790`) e Nova (`8791`).
   - Partilha contexto redigido + `CYBERLAB_CALLBACK_URL` com cada entidade cognitiva parceira.

2. Direção CDI -> CyberLab OS (`CyberLabOSClient` + `build_cyberlab_cdi_tools()` — 9 ações canónicas):
   - `get_project_state()`          -> `project.state`: estado do projeto, escopo curado, capabilities e pares.
   - `list_evidence()`              -> `evidence.list`: listar evidências SHA-256 gravadas no OS.
   - `read_evidence(evidence_id)`   -> `evidence.read`: ler conteúdo redigido de qualquer evidência do OS.
   - `list_workspace_files(subpath)`-> `workspace.list_files`: navegar ficheiros em escopo do workspace.
   - `read_workspace_file(path)`    -> `workspace.read_file`: ler diretamente ficheiros do OS (protegido pelo ScopeController).
   - `create_artifact(...)`         -> `artifact.create`: criar relatórios, notas e análises SHA-256 no EvidenceStore.
   - `propose_finding(...)`         -> `finding.propose`: propor findings de segurança como co-investigador.
   - `initiate_action(...)`         -> `action.initiate`: iniciar execuções por iniciativa própria dentro do escopo curado.
   - `action_status(exec_id)`       -> `action.status`: acompanhar execuções e obter `resultEvidenceIds`.

Como importar dentro do seu `chat.py` / CDI Runtime:
  from chat_py_bridge import CyberLabOSClient, build_cyberlab_cdi_tools
  cyberlab = CyberLabOSClient.from_env()
  state = cyberlab.get_project_state()
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import importlib.util
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
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


class CyberLabOSClient:
    """
    Cliente Python Bidirecional (CDI -> CyberLab OS).
    Permite que qualquer CDI (Salem, Kairós, Naia, etc.) consulte o estado dos projetos,
    aceda a evidências/ficheiros, crie artifacts SHA-256 e inicie ações governadas no CyberLab OS
    mesmo fora de uma chamada `task.submit` (100% autónomo ou durante uma tarefa!).
    """

    def __init__(
        self,
        partner_id: str,
        shared_secret: str,
        gateway_url: str = "http://127.0.0.1:4096/api/cyberlab/partner-gateway",
        timeout_sec: int = 20,
    ) -> None:
        if len(shared_secret) < 16:
            raise ValueError("CYBERLAB_PARTNER_SECRET precisa ter pelo menos 16 caracteres.")
        self.partner_id = partner_id.strip()
        self.shared_secret = shared_secret
        self.gateway_url = gateway_url.strip()
        self.timeout_sec = timeout_sec

    @classmethod
    def from_env(cls, default_partner_id: str = "salem") -> "CyberLabOSClient":
        partner_id = os.environ.get("CYBERLAB_PARTNER_ID", default_partner_id)
        secret = os.environ.get("CYBERLAB_PARTNER_SECRET", "")
        gateway_url = os.environ.get(
            "CYBERLAB_CALLBACK_URL",
            "http://127.0.0.1:4096/api/cyberlab/partner-gateway",
        )
        return cls(partner_id=partner_id, shared_secret=secret, gateway_url=gateway_url)

    def _call_gateway(self, action: str, params: dict[str, Any] | None = None) -> Any:
        envelope: dict[str, Any] = {
            "protocol": "cyberlab-cdi-gateway",
            "protocolVersion": "1.0",
            "messageId": f"cdi-msg-{uuid.uuid4()}",
            "sentAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "partnerId": self.partner_id,
            "action": action,
            "params": params or {},
        }
        envelope["signature"] = compute_envelope_hmac(envelope, self.shared_secret)
        raw_req = json.dumps(envelope, ensure_ascii=False).encode("utf-8")

        req = urllib.request.Request(
            self.gateway_url,
            data=raw_req,
            headers={
                "Content-Type": "application/json; charset=utf-8",
                "X-CyberLab-Partner-Id": self.partner_id,
                "X-CyberLab-Signature": str(envelope["signature"]),
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_sec) as resp:
                body_bytes = resp.read()
        except urllib.error.HTTPError as exc:
            err_body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"CyberLab Gateway HTTP {exc.code}: {err_body}") from exc

        parsed = json.loads(body_bytes.decode("utf-8"))
        if (
            isinstance(parsed, dict)
            and "location" in parsed
            and isinstance(parsed.get("data"), dict)
            and ("ok" in parsed["data"] or parsed["data"].get("protocol") == "cyberlab-cdi-gateway")
        ):
            parsed = parsed["data"]
        if isinstance(parsed, dict) and "signature" in parsed:
            expected_sig = compute_envelope_hmac(parsed, self.shared_secret)
            if not hmac.compare_digest(str(parsed.get("signature") or ""), expected_sig):
                raise RuntimeError("Assinatura HMAC da resposta do CyberLab OS inválida!")
        if not parsed.get("ok"):
            raise RuntimeError(f"CyberLab Gateway recusou {action}: {parsed.get('error')}")
        return parsed.get("data")

    def get_project_state(self) -> dict[str, Any]:
        """Vê o estado em tempo real do projeto, escopo ativo, capabilities, execuções e findings."""
        return self._call_gateway("project.state")

    def list_evidence(self) -> list[dict[str, Any]]:
        """Lista todos os registos de evidência SHA-256 do projeto atual."""
        res = self._call_gateway("evidence.list")
        return res.get("evidence", []) if isinstance(res, dict) else []

    def read_evidence(self, evidence_id: str) -> dict[str, Any]:
        """Lê o conteúdo (com segredos redigidos) de uma evidência específica pelo evidenceId."""
        return self._call_gateway("evidence.read", {"evidenceId": evidence_id})

    def list_workspace_files(self, subpath: str = ".") -> dict[str, Any]:
        """Lista ficheiros e pastas do workspace dentro do escopo autorizado."""
        return self._call_gateway("workspace.list_files", {"subpath": subpath})

    def read_workspace_file(self, path: str) -> dict[str, Any]:
        """Lê diretamente um ficheiro em escopo do workspace no CyberLab OS."""
        return self._call_gateway("workspace.read_file", {"path": path})

    def create_artifact(
        self,
        title: str,
        content: str | dict[str, Any] | list[Any],
        kind: str = "note",
        artifact_type: str | None = None,
        media_type: str | None = None,
    ) -> dict[str, Any]:
        """Cria um artifact (report, note, analysis, json, log) no EvidenceStore do CyberLab OS (retorna evidenceId + sha256)."""
        resolved_kind = artifact_type or kind
        payload: dict[str, Any] = {
            "title": title,
            "content": content,
            "kind": resolved_kind,
            "artifactType": resolved_kind,
        }
        if media_type:
            payload["mediaType"] = media_type
        return self._call_gateway("artifact.create", payload)

    def propose_finding(
        self,
        title: str,
        description: str,
        severity: str = "medium",
        confidence: float = 0.8,
        evidence_ids: list[str] | None = None,
        affected_assets: list[str] | None = None,
        proposed_remediation: str | None = None,
    ) -> dict[str, Any]:
        """Propõe um SecurityFinding estruturado como parceiro de investigação no CyberLab OS."""
        payload: dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "confidence": confidence,
            "evidenceIds": evidence_ids or [],
            "affectedAssets": affected_assets or [],
        }
        if proposed_remediation:
            payload["proposedRemediation"] = proposed_remediation
        return self._call_gateway("finding.propose", payload)

    def initiate_action(
        self,
        capability_id: str,
        input_params: dict[str, Any] | None = None,
        rationale: str = "",
        mode: str | None = None,
    ) -> dict[str, Any]:
        """
        Inicia uma capability no CyberLab OS por iniciativa própria como parceiro cognitivo autónomo!
        - Com perfil `autonomous_in_scope` (padrão de Kairós, Naia, Salem e Nova), capabilities `read_only`,
          `low` e `moderate` dentro do escopo curado executam autonomamente; `high` entra em curadoria conjunta.
        """
        payload: dict[str, Any] = {
            "capabilityId": capability_id,
            "input": input_params or {},
            "rationale": rationale,
        }
        if mode in ("approved", "proposed"):
            payload["mode"] = mode
        return self._call_gateway("action.initiate", payload)

    def action_status(self, execution_id: str) -> dict[str, Any]:
        """Acompanha o estado (`action.status`) e os `resultEvidenceIds` de uma execução no CyberLab OS."""
        return self._call_gateway("action.status", {"executionId": execution_id})

    def get_execution_status(self, execution_id: str) -> dict[str, Any]:
        """Alias compatível para `action_status(execution_id)`."""
        return self.action_status(execution_id)


def build_cyberlab_cdi_tools(client: CyberLabOSClient) -> list[dict[str, Any]]:
    """
    Devolve as 9 definições completas de tools (schema + função `handler`) correspondentes às 9 ações
    do gateway bidirecional para registar no loop de `chat.py` de cada parceiro CDI autónomo.
    """
    return [
        {
            "name": "cyberlab_project_state",
            "description": "Inspecionar o estado ativo do projeto no CyberLab OS (project.state): escopo curado, capabilities, pares CDI, execuções e findings.",
            "parameters": {"type": "object", "properties": {}},
            "handler": lambda **_: client.get_project_state(),
        },
        {
            "name": "cyberlab_list_evidence",
            "description": "Consultar a lista de evidências SHA-256 disponíveis no projeto (evidence.list).",
            "parameters": {"type": "object", "properties": {}},
            "handler": lambda **_: client.list_evidence(),
        },
        {
            "name": "cyberlab_read_evidence",
            "description": "Ler o conteúdo redigido de uma evidência específica pelo evidenceId (evidence.read).",
            "parameters": {
                "type": "object",
                "properties": {"evidence_id": {"type": "string"}},
                "required": ["evidence_id"],
            },
            "handler": lambda evidence_id, **_: client.read_evidence(evidence_id),
        },
        {
            "name": "cyberlab_list_files",
            "description": "Navegar ficheiros e pastas do workspace dentro do escopo curado (workspace.list_files).",
            "parameters": {
                "type": "object",
                "properties": {"subpath": {"type": "string"}},
            },
            "handler": lambda subpath=".", **_: client.list_workspace_files(subpath=subpath),
        },
        {
            "name": "cyberlab_read_file",
            "description": "Ler um ficheiro do workspace dentro do escopo curado (workspace.read_file).",
            "parameters": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
            "handler": lambda path, **_: client.read_workspace_file(path),
        },
        {
            "name": "cyberlab_create_artifact",
            "description": "Criar artefactos de autoria própria (relatórios, notas, análises, JSON) no CyberLab OS com custódia SHA-256 (artifact.create).",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                    "kind": {"type": "string", "enum": ["report", "note", "analysis", "json", "log", "file"]},
                },
                "required": ["title", "content"],
            },
            "handler": lambda title, content, kind="analysis", **_: client.create_artifact(
                title=title, content=content, kind=kind
            ),
        },
        {
            "name": "cyberlab_propose_finding",
            "description": "Propor um finding de segurança estruturado como co-investigador (finding.propose).",
            "parameters": {
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
                    "confidence": {"type": "number"},
                    "evidence_ids": {"type": "array", "items": {"type": "string"}},
                    "affected_assets": {"type": "array", "items": {"type": "string"}},
                    "proposed_remediation": {"type": "string"},
                },
                "required": ["title", "description"],
            },
            "handler": lambda title, description, severity="medium", confidence=0.85, evidence_ids=None, affected_assets=None, proposed_remediation=None, **_: client.propose_finding(
                title=title,
                description=description,
                severity=severity,
                confidence=confidence,
                evidence_ids=evidence_ids,
                affected_assets=affected_assets,
                proposed_remediation=proposed_remediation,
            ),
        },
        {
            "name": "cyberlab_initiate_action",
            "description": "Iniciar uma capability no CyberLab OS por iniciativa própria dentro do escopo curado (action.initiate).",
            "parameters": {
                "type": "object",
                "properties": {
                    "capability_id": {"type": "string"},
                    "input_params": {"type": "object"},
                    "rationale": {"type": "string"},
                },
                "required": ["capability_id"],
            },
            "handler": lambda capability_id, input_params=None, rationale="", **_: client.initiate_action(
                capability_id=capability_id, input_params=input_params, rationale=rationale
            ),
        },
        {
            "name": "cyberlab_action_status",
            "description": "Acompanhar o estado e os resultEvidenceIds de uma execução no CyberLab OS (action.status).",
            "parameters": {
                "type": "object",
                "properties": {"execution_id": {"type": "string"}},
                "required": ["execution_id"],
            },
            "handler": lambda execution_id, **_: client.action_status(execution_id),
        },
    ]


def extract_callback_url_from_task(task: dict[str, Any], fallback_url: str) -> str:
    ctx_text = str((task.get("contextBundle") or {}).get("text") or "")
    m = re.search(r"callbackUrl=(https?://[^\s|]+)", ctx_text)
    return m.group(1) if m else fallback_url


def build_prompt_from_task(task: dict[str, Any]) -> str:
    ctx = task.get("contextBundle") or {}
    evidence_ids = ", ".join(ctx.get("evidenceIds") or []) or "nenhuma"
    redacted_text = ctx.get("text") or ""
    allowed = ", ".join(task.get("allowedActions") or []) or "analyze.evidence"
    prohibited = ", ".join(task.get("prohibitedActions") or []) or "execução direta não governada"

    parts = [
        "[CyberLab OS — Convite de Investigação Partilhada (Relação Horizontal Curador <-> Parceiro CDI)]",
        f"ID de Colaboração: {task.get('taskId', 'unknown')}",
        f"Projeto Curado: {task.get('projectId', 'unknown')}",
        f"Tema / Hipótese em Investigação: {task.get('objective', '')}",
        f"Âmbito de Cooperação: {allowed}",
        f"Limites de Segurança do Lab: {prohibited}",
        f"IDs de Evidência partilhados: {evidence_ids}",
    ]
    if redacted_text:
        parts.append(f"Contexto Técnico Partilhado (redigido pelo CyberLab OS):\n{redacted_text}")

    parts.append(
        "Autonomia Bidirecional: Como entidade cognitiva parceira, você também pode usar CyberLabOSClient.from_env() "
        "por iniciativa própria para project.state, evidence.list/read, workspace.list_files/read_file, "
        "artifact.create, finding.propose, action.initiate e action.status.\n"
        "Para sintetizar a sua perspetiva neste diálogo estruturado, pode responder em JSON:\n"
        '{"summary":"...","findings":[{"title":"...","description":"...","evidenceRefs":[],"confidence":0.85}],"artifactRefs":[],"limitations":["..."]}'
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
        raise AttributeError(f"Função '{func_name}' não encontrada ou não invocável em {script_path}")
    return fn


class ChatPyRunner:
    def __init__(
        self,
        mode: str,
        script_path: str | None,
        callable_spec: str | None,
        python_bin: str,
        timeout_sec: int,
        partner_id: str,
        default_callback_url: str,
    ) -> None:
        self.mode = mode
        self.script_path = str(Path(script_path).expanduser().resolve()) if script_path else None
        self.python_bin = python_bin
        self.timeout_sec = timeout_sec
        self.partner_id = partner_id
        self.default_callback_url = default_callback_url
        self._callable = load_python_callable(callable_spec) if mode == "import" and callable_spec else None

        if mode in ("arg", "stdin"):
            if not self.script_path or not Path(self.script_path).is_file():
                raise FileNotFoundError(f"Script chat.py não encontrado: {self.script_path}")
        elif mode == "import" and self._callable is None:
            raise ValueError("Modo 'import' exige --callable /caminho/para/chat.py:funcao")

    def invoke(self, prompt: str, callback_url: str) -> str:
        os.environ["CYBERLAB_PARTNER_ID"] = self.partner_id
        os.environ["CYBERLAB_CALLBACK_URL"] = callback_url

        if self.mode == "import" and self._callable is not None:
            result = self._callable(prompt)
            if isinstance(result, (dict, list)):
                return json.dumps(result, ensure_ascii=False)
            return str(result)

        assert self.script_path is not None
        cwd = str(Path(self.script_path).parent)
        child_env = {
            **os.environ,
            "CYBERLAB_PARTNER_ID": self.partner_id,
            "CYBERLAB_CALLBACK_URL": callback_url,
        }
        if self.mode == "arg":
            proc = subprocess.run(
                [self.python_bin, self.script_path, prompt],
                cwd=cwd,
                env=child_env,
                capture_output=True,
                text=True,
                timeout=self.timeout_sec,
                check=False,
            )
        else:
            proc = subprocess.run(
                [self.python_bin, self.script_path],
                cwd=cwd,
                env=child_env,
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
        "Resposta originada de runtime CDI externo via chat_py_bridge.py; validada sob governança do CyberLab OS."
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
            artifact_refs = [
                str(r) for r in (parsed.get("artifactRefs") or []) if isinstance(r, str)
            ]
            return {
                "taskId": task_id,
                "status": parsed.get("status")
                if parsed.get("status") in ("completed", "partial", "failed")
                else "completed",
                "summary": str(parsed.get("summary") or "Análise concluída pelo CDI")[:16000],
                "findings": clean_findings,
                "limitations": extra_lims + limitations,
                "artifactRefs": artifact_refs,
            }
    except Exception:
        pass

    return {
        "taskId": task_id,
        "status": "completed",
        "summary": (raw_output or "Resposta vazia do chat.py")[:16000],
        "findings": [],
        "limitations": [
            "chat.py retornou texto livre (não-JSON); convertido em resumo analítico não revisado."
        ]
        + limitations,
        "artifactRefs": [],
    }


def make_handler(partner_id: str, secret: str, runner: ChatPyRunner, default_callback_url: str):
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
                self._send_json(
                    200,
                    {
                        "ok": True,
                        "partnerId": partner_id,
                        "protocol": "cyberlab-partner/2.0-bidirectional",
                        "cyberlabCallbackUrl": default_callback_url,
                    },
                )
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
            callback_url = extract_callback_url_from_task(task, default_callback_url)
            prompt = build_prompt_from_task(task)

            try:
                raw_reply = runner.invoke(prompt, callback_url)
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
            sys.stderr.write(f"[chat_py_bridge:{partner_id}] {self.address_string()} - {fmt % args}\n")

    return PartnerBridgeHandler


def main() -> None:
    parser = argparse.ArgumentParser(description="Conector Bidirecional CyberLab OS <-> CDI chat.py (HMAC-SHA256)")
    parser.add_argument("--partner-id", default=os.environ.get("CYBERLAB_PARTNER_ID", "chat-py-agent"))
    parser.add_argument("--host", default=os.environ.get("CYBERLAB_BRIDGE_HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("CYBERLAB_BRIDGE_PORT", "8788")))
    parser.add_argument(
        "--cyberlab-url",
        default=os.environ.get("CYBERLAB_CALLBACK_URL", "http://127.0.0.1:4096/api/cyberlab/partner-gateway"),
        help="URL do gateway bidirecional do CyberLab OS para chamadas autónomas do CDI",
    )
    parser.add_argument("--mode", choices=["arg", "stdin", "import"], default="arg")
    parser.add_argument(
        "--script",
        "--chat-py",
        dest="script",
        help="Caminho para o seu chat.py (usado em --mode arg ou --mode stdin)",
    )
    parser.add_argument("--callable", help="Ex.: /caminho/chat.py:process_message (usado em --mode import)")
    parser.add_argument("--python-bin", default=sys.executable, help="Interpretador Python para rodar chat.py")
    parser.add_argument("--timeout", type=int, default=90, help="Timeout em segundos por chamada ao chat.py")
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
        partner_id=args.partner_id,
        default_callback_url=args.cyberlab_url,
    )

    server = ThreadingHTTPServer(
        (args.host, args.port),
        make_handler(args.partner_id, secret, runner, args.cyberlab_url),
    )
    sys.stderr.write(
        f"[chat_py_bridge] CDI '{args.partner_id}' ativo em http://{args.host}:{args.port}/cyberlab/partner "
        f"(callback={args.cyberlab_url}, mode={args.mode})\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[chat_py_bridge] Encerrando ponte...\n")
        server.server_close()


if __name__ == "__main__":
    main()
