import os

from langchain_openai import ChatOpenAI

from .model_registry import build_main_model


def build_models(main_model_id: str | None = None, skip_sub: bool = False):
    # Main agent: advanced reasoning model
    if main_model_id:
        main_llm = build_main_model(main_model_id)
    else:
        raise ValueError("Main model id is required")

    if skip_sub:
        return main_llm, None

    # Subagent: vLLM-served GLM-4.7-Flash (OpenAI-compatible)
    # Using Z.ai recommended parameters for Tool-calling:
    # --temp 0.7 --top-p 1.0
    sub_llm = ChatOpenAI(
        base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
        api_key=os.getenv("VLLM_API_KEY", "EMPTY"),
        model=os.getenv("VLLM_MODEL", "glm-4.7-flash"),
        temperature=0.7,
        top_p=1.0
    )
    return main_llm, sub_llm
