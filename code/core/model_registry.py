from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from langchain_anthropic import ChatAnthropic
from langchain_google_genai import ChatGoogleGenerativeAI
from langchain_openai import ChatOpenAI

SUPPORTED_BACKENDS = {"openai_compatible", "anthropic", "gemini"}
DEFAULT_MODELS_CONFIG = (
    Path(__file__).resolve().parents[1] / "config" / "models.json"
)


@dataclass(frozen=True)
class ModelSpec:
    model_id: str
    backend: str
    model: str
    base_url_env: str | None
    api_key_env: str
    params: dict[str, object] | None


def _require_field(raw: dict[str, object], key: str, model_id: str) -> object:
    if key not in raw:
        raise ValueError(
            f"Model '{model_id}' is missing required field '{key}' in models.json"
        )
    return raw[key]


def load_model_registry(
    config_path: Path | None = None,
) -> dict[str, ModelSpec]:
    config_path = config_path or DEFAULT_MODELS_CONFIG
    if not config_path.exists():
        raise FileNotFoundError(f"Models config not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)

    if not isinstance(payload, dict):
        raise ValueError("models.json must be a JSON object")

    models = payload.get("models")
    if not isinstance(models, list):
        raise ValueError("models.json must contain a top-level 'models' list")

    registry: dict[str, ModelSpec] = {}
    for index, raw in enumerate(models):
        if not isinstance(raw, dict):
            raise ValueError(f"Model entry at index {index} must be an object")

        model_id = _require_field(raw, "id", f"index {index}")
        if not isinstance(model_id, str) or not model_id:
            raise ValueError(
                f"Model entry at index {index} must have a non-empty string 'id'"
            )

        backend = _require_field(raw, "backend", model_id)
        if not isinstance(backend, str) or backend not in SUPPORTED_BACKENDS:
            raise ValueError(
                f"Model '{model_id}' has unsupported backend '{backend}'"
            )

        model = _require_field(raw, "model", model_id)
        if not isinstance(model, str) or not model:
            raise ValueError(
                f"Model '{model_id}' must define a non-empty string 'model'"
            )

        api_key_env = _require_field(raw, "api_key_env", model_id)
        if not isinstance(api_key_env, str) or not api_key_env:
            raise ValueError(
                f"Model '{model_id}' must define a non-empty 'api_key_env'"
            )

        base_url_env = raw.get("base_url_env")
        if isinstance(base_url_env, str) and base_url_env.strip() == "":
            base_url_env = None
        elif base_url_env is not None and not isinstance(base_url_env, str):
            raise ValueError(
                f"Model '{model_id}' has invalid 'base_url_env' value"
            )

        params = raw.get("params")
        if params is None:
            params = None
        elif not isinstance(params, dict):
            raise ValueError(
                f"Model '{model_id}' has invalid 'params' value (must be an object)"
            )
        else:
            if any(not isinstance(key, str) for key in params.keys()):
                raise ValueError(
                    f"Model '{model_id}' has non-string keys in 'params'"
                )
            reserved = {"model", "api_key", "base_url"}
            collisions = sorted(reserved.intersection(params.keys()))
            if collisions:
                raise ValueError(
                    f"Model '{model_id}' has reserved keys in 'params': "
                    f"{', '.join(collisions)}"
                )
            if not params:
                params = None

        if model_id in registry:
            raise ValueError(f"Duplicate model id '{model_id}' in models.json")

        registry[model_id] = ModelSpec(
            model_id=model_id,
            backend=backend,
            model=model,
            base_url_env=base_url_env,
            api_key_env=api_key_env,
            params=params,
        )

    return registry


def build_main_model(model_id: str, config_path: Path | None = None):
    registry = load_model_registry(config_path)
    spec = registry.get(model_id)
    if spec is None:
        raise ValueError(f"Unknown model id '{model_id}'")

    base_url = os.getenv(spec.base_url_env) if spec.base_url_env else None
    api_key = os.getenv(spec.api_key_env)
    if not api_key:
        raise ValueError(
            f"Missing API key for model '{model_id}': "
            f"env var {spec.api_key_env} is not set"
        )

    params = dict(spec.params) if spec.params else {}
    if spec.backend == "openai_compatible":
        return ChatOpenAI(
            base_url=base_url,
            api_key=api_key,
            model=spec.model,
            **params,
        )
    if spec.backend == "gemini":
        return ChatGoogleGenerativeAI(
            model=spec.model, api_key=api_key, base_url=base_url, **params
        )
    if spec.backend == "anthropic":
        return ChatAnthropic(
            model=spec.model, api_key=api_key, base_url=base_url, **params
        )

    raise ValueError(f"Unsupported backend '{spec.backend}'")


def build_instructor_client(
    model_id: str,
    config_path: Path | None = None,
    *,
    async_client: bool = True,
):
    registry = load_model_registry(config_path)
    spec = registry.get(model_id)
    if spec is None:
        raise ValueError(f"Unknown model id '{model_id}'")

    base_url = os.getenv(spec.base_url_env) if spec.base_url_env else None
    api_key = os.getenv(spec.api_key_env)
    if not api_key:
        raise ValueError(
            f"Missing API key for model '{model_id}': "
            f"env var {spec.api_key_env} is not set"
        )

    import instructor

    if spec.backend == "openai_compatible":
        return instructor.from_provider(
            f"openai/{spec.model}",
            async_client=async_client,
            api_key=api_key,
            base_url=base_url,
        )
    if spec.backend == "anthropic":
        import anthropic

        if async_client:
            client = anthropic.AsyncAnthropic(
                api_key=api_key,
                base_url=base_url,
            )
        else:
            client = anthropic.Anthropic(
                api_key=api_key,
                base_url=base_url,
            )
        return instructor.from_anthropic(
            client,
            model=spec.model,
            mode=instructor.Mode.ANTHROPIC_TOOLS,
        )
    if spec.backend == "gemini":
        return instructor.from_provider(
            f"google/{spec.model}",
            async_client=async_client,
            api_key=api_key,
        )

    raise ValueError(f"Unsupported backend '{spec.backend}'")
