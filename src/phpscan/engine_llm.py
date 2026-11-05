"""Phase 7 bis - moteur LLM : l'analyse est déléguée à un modèle via une API distante.

Trajet d'un fichier
-------------------
1. construire le prompt (prompts/v2.txt, lignes numérotées)
2. regarder le cache disque : même modèle + même prompt + même code -> réponse gardée
3. sinon appeler l'API, avec timeout et nouvelles tentatives (429, 5xx, réseau)
4. valider la réponse JSON (structure, numéros de ligne, règles connues)
5. convertir en Finding, comme les moteurs regex et ast
6. comptabiliser jetons et coût

Configuration (variables d'environnement, ou fichier .env à la racine du projet) :
    PHPSCAN_LLM_PROVIDER  groq (défaut, offre gratuite, API compatible OpenAI) ou anthropic
    ANTHROPIC_API_KEY     clé API Anthropic (fournisseur anthropic)
    GROQ_API_KEY          clé API Groq (fournisseur groq)
    PHPSCAN_LLM_MODEL     modèle (défaut : claude-haiku-5-5 ou openai/gpt-oss-20b)
    PHPSCAN_LLM_RUN     numéro de lancement, entre dans la clé du cache (défaut : 0)
    PHPSCAN_LLM_CACHE   0 pour désactiver le cache (défaut : 1)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from .models import Finding, Rule

ROOT = Path(__file__).resolve().parents[2]
PROMPT_VERSION = "v2"
PROMPT_PATH = ROOT / "prompts" / f"{PROMPT_VERSION}.txt"
CACHE_DIR = Path(os.environ.get("PHPSCAN_LLM_CACHE_DIR", ".cache/llm"))
DEFAULT_MODELS = {"anthropic": "claude-haiku-5-5", "groq": "openai/gpt-oss-20b"}
GROQ_BASE_URL = "https://api.groq.com/openai/v1"
MAX_TOKENS = 1024
TIMEOUT_S = 60.0
MAX_ATTEMPTS = 4          # 1 appel + 3 nouvelles tentatives
BACKOFF_BASE_S = 1.0      # 1 s, 2 s, 4 s

# Prix en dollars par million de jetons (entrée, sortie), prompts de moins de 100k jetons.
# Source : https://platform.claude.com/docs/en/about-claude/pricing (novembre 2026)
PRICES = {
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-sonnet-5-5": (2.0, 10.0),
    "claude-opus-5-5": (4.0, 20.0),
    # Groq, offre gratuite (limites de débit, pas de facturation)
    "openai/gpt-oss-20b": (0.0, 0.0),
    "openai/gpt-oss-120b": (0.0, 0.0),
}


# ---------------------------------------------------------------- configuration

def load_dotenv(path: Path = Path(".env")) -> None:
    """Charge un fichier .env minimal (CLE=valeur) sans écraser l'environnement existant."""
    if not path.is_file():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip("'\""))


class LLMError(RuntimeError):
    pass


# ---------------------------------------------------------------- client

@dataclass
class Completion:
    text: str
    input_tokens: int
    output_tokens: int


class LLMClient(Protocol):
    model: str

    def complete(self, prompt: str) -> Completion: ...


RULE_IDS = ["PHP-SQLI-001", "PHP-EXEC-001", "PHP-SECRET-001", "PHP-HASH-001", "PHP-INPUT-001"]

# Sortie structurée : l'API garantit une réponse conforme à ce schéma JSON.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "line": {"type": "integer"},
                    "rule_id": {"type": "string", "enum": RULE_IDS},
                    "explanation": {"type": "string"},
                },
                "required": ["line", "rule_id", "explanation"],
                "additionalProperties": False,
            },
        },
    },
    "required": ["findings"],
    "additionalProperties": False,
}


class AnthropicClient:
    """Appel à l'API Messages d'Anthropic, avec nouvelles tentatives gérées ici.

    Le SDK actuel n'expose plus de paramètre de température : le modèle n'est donc pas
    déterministe : deux lancements peuvent donner des résultats différents.
    """

    def __init__(self, model: str, api_key: str):
        try:
            import anthropic
        except ImportError as e:  # pragma: no cover
            raise SystemExit("Moteur LLM indisponible : pip install -e '.[llm]'") from e
        self._anthropic = anthropic
        # max_retries=0 : la politique de nouvelles tentatives est la nôtre, visible et testée
        self._client = anthropic.Anthropic(api_key=api_key, timeout=TIMEOUT_S, max_retries=0)
        self.model = model

    def _retryable(self, err: Exception) -> bool:
        """Temporaire (on réessaie) : 429, 5xx, réseau. Définitive : 400, 401, 403, 404..."""
        a = self._anthropic
        if isinstance(err, (a.RateLimitError, a.APIConnectionError, a.APITimeoutError)):
            return True
        return isinstance(err, a.APIStatusError) and err.status_code >= 500

    def is_fatal(self, err: Exception) -> bool:
        """Clé invalide ou refusée : inutile de continuer sur les autres fichiers."""
        a = self._anthropic
        return isinstance(err.__cause__, (a.AuthenticationError, a.PermissionDeniedError))

    def complete(self, prompt: str) -> Completion:
        def call() -> Completion:
            msg = self._client.messages.create(
                model=self.model, max_tokens=MAX_TOKENS,
                messages=[{"role": "user", "content": prompt}],
                output_config={"format": {"type": "json_schema", "schema": RESPONSE_SCHEMA}},
            )
            text = "".join(getattr(b, "text", "") for b in msg.content if b.type == "text")
            return Completion(text, msg.usage.input_tokens, msg.usage.output_tokens)

        return with_retries(call, self._retryable)


class HTTPError(Exception):
    """Erreur HTTP d'une API compatible OpenAI, avec son code et l'éventuel Retry-After."""

    def __init__(self, status: int, body: str, retry_after: float | None = None):
        super().__init__(f"HTTP {status}: {body[:200]}")
        self.status, self.retry_after = status, retry_after


class OpenAICompatibleClient:
    """Client HTTP minimal (bibliothèque standard) pour une API au format OpenAI : Groq...

    Écrit sans SDK pour montrer le protocole : POST JSON, en-tête Authorization: Bearer,
    codes HTTP, Retry-After, sortie structurée via response_format json_schema.
    """

    def __init__(self, model: str, api_key: str, base_url: str = GROQ_BASE_URL,
                 opener=urllib.request.urlopen):
        self.model, self._key, self._url, self._open = model, api_key, base_url, opener

    def _retryable(self, err: Exception) -> bool:
        if isinstance(err, HTTPError):
            return err.status == 429 or err.status >= 500
        return isinstance(err, (urllib.error.URLError, TimeoutError))

    def is_fatal(self, err: Exception) -> bool:
        return isinstance(err.__cause__, HTTPError) and err.__cause__.status in (401, 403)

    def _post(self, payload: dict) -> dict:
        req = urllib.request.Request(
            f"{self._url}/chat/completions", data=json.dumps(payload).encode(), method="POST",
            headers={"Authorization": f"Bearer {self._key}", "Content-Type": "application/json",
                     "User-Agent": "phpscan"},
        )
        try:
            with self._open(req, timeout=TIMEOUT_S) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            retry = e.headers.get("Retry-After") if e.headers else None
            raise HTTPError(e.code, e.read().decode("utf-8", "replace"),
                            float(retry) if retry and retry.replace(".", "").isdigit() else None
                            ) from None

    def complete(self, prompt: str) -> Completion:
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_completion_tokens": 4 * MAX_TOKENS,   # les modèles gpt-oss raisonnent avant
            "response_format": {"type": "json_schema", "json_schema": {
                "name": "phpscan_findings", "strict": True, "schema": RESPONSE_SCHEMA}},
        }

        def call() -> Completion:
            data = self._post(payload)
            usage = data.get("usage") or {}
            text = data["choices"][0]["message"].get("content") or ""
            return Completion(text, int(usage.get("prompt_tokens", 0)),
                              int(usage.get("completion_tokens", 0)))

        return with_retries(call, self._retryable)


def with_retries(call, retryable, attempts: int = MAX_ATTEMPTS, base: float = BACKOFF_BASE_S,
                 sleep=time.sleep):
    """Exécute `call`, réessaie avec attente exponentielle si l'erreur est temporaire."""
    for attempt in range(attempts):
        try:
            return call()
        except Exception as err:
            if not retryable(err) or attempt == attempts - 1:
                raise LLMError(f"échec de l'appel API : {type(err).__name__}: {err}") from err
            # le serveur peut indiquer combien attendre (limite de débit) : on le respecte
            wait = getattr(err, "retry_after", None) or base * 2 ** attempt
            sleep(wait)
    raise AssertionError("inaccessible")  # pragma: no cover


# ---------------------------------------------------------------- statistiques

@dataclass
class Usage:
    calls: int = 0
    cache_hits: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    invalid_responses: int = 0
    dropped_findings: int = 0          # lignes inexistantes, règles inconnues
    errors: list[str] = field(default_factory=list)

    def cost(self, model: str) -> float | None:
        price = PRICES.get(model)
        if price is None:
            return None
        return (self.input_tokens * price[0] + self.output_tokens * price[1]) / 1_000_000

    def summary(self, model: str) -> str:
        cost = self.cost(model)
        cost_s = "inconnu" if cost is None else ("gratuit" if PRICES[model] == (0.0, 0.0)
                                                  else f"{cost:.4f} $")
        return (f"[llm] modèle {model} - {self.calls} appel(s), {self.cache_hits} en cache, "
                f"{self.input_tokens} jetons entrée / {self.output_tokens} sortie, coût {cost_s}, "
                f"{self.invalid_responses} réponse(s) invalide(s), "
                f"{self.dropped_findings} alerte(s) rejetée(s), {len(self.errors)} erreur(s)")


USAGE = Usage()
_client: LLMClient | None = None


def get_client() -> LLMClient:
    global _client
    if _client is None:
        load_dotenv()
        provider = os.environ.get("PHPSCAN_LLM_PROVIDER", "groq").lower()
        if provider not in DEFAULT_MODELS:
            raise SystemExit(f"PHPSCAN_LLM_PROVIDER inconnu : {provider} (anthropic ou groq)")
        key_name = "GROQ_API_KEY" if provider == "groq" else "ANTHROPIC_API_KEY"
        key = os.environ.get(key_name)
        if not key:
            raise SystemExit(f"{key_name} manquante : ajoute-la dans .env ou l'environnement")
        model = os.environ.get("PHPSCAN_LLM_MODEL", DEFAULT_MODELS[provider])
        _client = (OpenAICompatibleClient(model, key) if provider == "groq"
                   else AnthropicClient(model, key))
    return _client


def set_client(client: LLMClient | None) -> None:
    """Injection d'un client (tests)."""
    global _client
    _client = client


# ---------------------------------------------------------------- prompt, cache, parsing

def build_prompt(code: str, filename: str) -> str:
    numbered = "\n".join(f"{i:>4} | {line}" for i, line in enumerate(code.splitlines(), 1))
    template = PROMPT_PATH.read_text(encoding="utf-8")
    # replace et non format : le code PHP contient des accolades
    return template.replace("{filename}", filename).replace("{code}", numbered)


def cache_key(model: str, prompt: str, run: int) -> str:
    raw = f"{model}\n{PROMPT_VERSION}\n{run}\n{prompt}".encode()
    return hashlib.sha256(raw).hexdigest()


def cached_complete(client: LLMClient, prompt: str, run: int) -> Completion:
    use_cache = os.environ.get("PHPSCAN_LLM_CACHE", "1") != "0"
    path = CACHE_DIR / f"{cache_key(client.model, prompt, run)}.json"
    if use_cache and path.is_file():
        USAGE.cache_hits += 1
        return Completion(**json.loads(path.read_text(encoding="utf-8")))
    comp = client.complete(prompt)
    USAGE.calls += 1
    USAGE.input_tokens += comp.input_tokens
    USAGE.output_tokens += comp.output_tokens
    if use_cache:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(comp.__dict__, ensure_ascii=False), encoding="utf-8")
    return comp


_JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


def parse_response(text: str) -> list[dict]:
    """Extrait la liste des alertes. Lève ValueError si la réponse n'est pas exploitable."""
    m = _JSON_OBJECT.search(text)          # tolère ```json ... ``` ou un texte parasite
    if m is None:
        raise ValueError("aucun objet JSON dans la réponse")
    data = json.loads(m.group())
    items = data.get("findings") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ValueError("clé 'findings' absente ou invalide")
    return [i for i in items if isinstance(i, dict)]


# ---------------------------------------------------------------- moteur

def scan_source(code: str, filename: str, rules: list[Rule]) -> list[Finding]:
    by_id = {r.id: r for r in rules}
    lines = code.splitlines()
    client = get_client()
    run = int(os.environ.get("PHPSCAN_LLM_RUN", "0"))
    try:
        comp = cached_complete(client, build_prompt(code, filename), run)
    except LLMError as e:
        if getattr(client, "is_fatal", lambda _e: False)(e):
            raise SystemExit(f"[llm] arrêt : clé API refusée ({e.__cause__})") from e
        USAGE.errors.append(f"{filename}: {e}")
        print(f"[llm] {filename} ignoré : {e}", file=sys.stderr)
        return []
    try:
        items = parse_response(comp.text)
    except (ValueError, json.JSONDecodeError):
        USAGE.invalid_responses += 1
        return []

    found: dict[tuple[str, int], Finding] = {}
    for item in items:
        rule = by_id.get(str(item.get("rule_id", "")))
        line = item.get("line")
        if rule is None or not isinstance(line, int) or not 1 <= line <= len(lines):
            USAGE.dropped_findings += 1     # hallucination : règle ou ligne inexistante
            continue
        if "phpscan-ignore" in lines[line - 1]:
            continue
        found.setdefault((rule.id, line), Finding(
            file=filename, line=line, column=1, rule_id=rule.id, severity=rule.severity,
            message=str(item.get("explanation") or rule.message)[:300], fix=rule.fix,
            snippet=lines[line - 1].strip(), engine="llm",
        ))
    return sorted(found.values(), key=lambda f: (f.line, f.rule_id))


def scan_file(path: Path, rules: list[Rule]) -> list[Finding]:
    from .loader import read_source

    return scan_source(read_source(path), str(path), rules)
