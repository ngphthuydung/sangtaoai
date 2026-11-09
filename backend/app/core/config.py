"""
Core configuration module for Lá Chắn Người Thân Backend.
"""
from typing import List, Union
from pydantic import Field, SecretStr, ValidationError, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
import json


class Settings(BaseSettings):
    """
    Quản lý các biến môi trường cấu hình an toàn cho hệ thống.
    Đọc tự động từ file .env hoặc biến môi trường hệ thống.
    """
    PROJECT_NAME: str = "Lá Chắn Người Thân - Backend API"
    VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "127.0.0.1"

    AI_ENABLED: bool = False
    OPENAI_API_KEY: str | None = None
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    GEMINI_API_KEY: str | None = None
    GEMINI_MODEL: str = "gemini-3.5-flash-lite"
    GEMINI_BASE_URL: str = "https://generativelanguage.googleapis.com/v1beta"
    AI_TIMEOUT_SECONDS: float = Field(default=20.0, gt=0, le=60)
    AI_MAX_INPUT_CHARS: int = Field(default=12000, gt=0, le=30000)
    AI_MAX_CONCURRENT_REQUESTS: int = Field(default=2, gt=0, le=20)
    AI_MAX_OUTPUT_TOKENS: int = Field(default=1200, gt=0, le=4000)

    # CORS Origins: Danh sách các nguồn gốc (Frontend) được phép giao tiếp với API
    CORS_ORIGINS: Union[List[str], str] = ["http://localhost:5173", "http://127.0.0.1:5173", "https://musical-sniffle-96xjvj59xgrvfp564-5173.app.github.dev"]

    SECRET_KEY: SecretStr = Field(min_length=32, repr=False)

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.strip().startswith("[") and v.strip().endswith("]"):
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:5173", "http://127.0.0.1:5173"]

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


def load_settings() -> Settings:
    try:
        return Settings()
    except ValidationError as error:
        invalid_fields = {
            str(issue["loc"][0])
            for issue in error.errors()
            if issue.get("loc")
        }
        if "SECRET_KEY" in invalid_fields:
            raise RuntimeError(
                "Configuration error: SECRET_KEY must be set in the environment "
                "or backend .env file and contain at least 32 characters."
            ) from None

        fields = ", ".join(sorted(invalid_fields)) or "unknown settings"
        raise RuntimeError(
            f"Configuration error: invalid settings for {fields}."
        ) from None


settings = load_settings()
