"""
TrustLens Configuration - Settings Management

Loads configuration from environment variables with sensible defaults.
Secrets are masked in __repr__ for safe logging.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from dotenv import load_dotenv

# Load .env once, before any Settings instance reads the environment.
load_dotenv()

_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


@dataclass(frozen=True, slots=True)
class Settings:
    """Application settings loaded from environment variables."""

    anthropic_api_key: str = field(default="", metadata={"env": "ANTHROPIC_API_KEY"})
    groq_api_key: str = field(default="", metadata={"env": "GROQ_API_KEY"})
    nvidia_api_key: str = field(default="", metadata={"env": "NVIDIA_API_KEY"})
    urlhaus_api_key: str = field(default="", metadata={"env": "URLHAUS_API_KEY"})
    rpc_url: str = field(default="http://127.0.0.1:8545", metadata={"env": "RPC_URL"})
    contract_address: str = field(default="", metadata={"env": "CONTRACT_ADDRESS"})
    private_key: str = field(default="", metadata={"env": "PRIVATE_KEY"})
    db_path: str = field(default="trustlens.db", metadata={"env": "DB_PATH"})
    offline_mode: bool = field(default=False, metadata={"env": "OFFLINE_MODE"})

    def __post_init__(self) -> None:
        """Load values from environment after initialization."""
        for f in self.__dataclass_fields__.values():
            env_name = f.metadata.get("env")
            if env_name and env_name in os.environ:
                value = os.environ[env_name]
                # ``from __future__ import annotations`` makes f.type a string
                if f.type in (bool, "bool"):
                    object.__setattr__(self, f.name, value.strip().lower() in _TRUE_VALUES)
                else:
                    object.__setattr__(self, f.name, value)

    def __repr__(self) -> str:
        """Mask secrets in representation."""
        masked = {}
        for f in self.__dataclass_fields__.values():
            value = getattr(self, f.name)
            if "key" in f.name.lower() or "private" in f.name.lower():
                masked[f.name] = "***" if value else ""
            else:
                masked[f.name] = value
        return f"Settings({masked})"

    def get(self, key: str, default: Any = None) -> Any:
        """Get setting value by key."""
        return getattr(self, key, default)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


# Module-level instance for convenience
settings = get_settings()