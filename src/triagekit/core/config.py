from functools import lru_cache
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        populate_by_name=True,
    )

    github_token: Optional[str] = Field(default=None, validation_alias="GITHUB_TOKEN")

    # LLM — any OpenAI-compatible provider (OpenAI, NVIDIA NIM, Ollama, etc.)
    # Prefer LLM_* names; OPENAI_* kept for backward compatibility
    llm_api_key: Optional[str] = Field(default=None, validation_alias="LLM_API_KEY")
    llm_base_url: Optional[str] = Field(default=None, validation_alias="LLM_BASE_URL")
    llm_model: Optional[str] = Field(default=None, validation_alias="LLM_MODEL")

    openai_api_key: Optional[str] = Field(default=None, validation_alias="OPENAI_API_KEY")
    openai_base_url: Optional[str] = Field(default=None, validation_alias="OPENAI_BASE_URL")
    openai_model: str = Field(default="gpt-4o", validation_alias="OPENAI_MODEL")

    temperature: float = 0.08
    max_tokens: int = 5000

    critical_paths: list[str] = Field(default_factory=lambda: [
        "src/", "lib/", "core/", "pkg/", "internal/", "auth", "security", "crypto",
        "migration", "migrations", "schema", "db/", "database", "api/", "middleware",
        "config", "settings", "secrets", "handler", "controller", "service",
    ])
    security_paths: list[str] = Field(default_factory=lambda: [
        "auth", "security", "crypto", "password", "passwd", "token", "secret", "key",
        "cert", "oauth", "jwt", "session", "permission", "rbac", "acl", "cors",
        "csrf", "xss", "sanitize", "encrypt", "decrypt", "hash",
    ])
    api_surface_paths: list[str] = Field(default_factory=lambda: [
        "api/", "public/", "export", "index.ts", "index.js", "mod.rs", "__init__.py",
        "routes", "endpoints", "handlers", "controllers",
    ])

    host: str = Field(default="127.0.0.1", validation_alias="TRIAGEKIT_HOST")
    port: int = Field(default=8000, validation_alias="TRIAGEKIT_PORT")

    def resolved_api_key(self) -> Optional[str]:
        return self.llm_api_key or self.openai_api_key

    def resolved_base_url(self) -> Optional[str]:
        return self.llm_base_url or self.openai_base_url

    def resolved_model(self) -> str:
        return self.llm_model or self.openai_model


@lru_cache
def get_settings() -> Settings:
    return Settings()
