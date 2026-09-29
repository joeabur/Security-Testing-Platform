"""Where the CLI keeps its base URL and credential.

The token is read from the environment first, because that is how CI supplies
it and an environment variable is not left behind on a shared machine. The
config file is the convenience for a person at a terminal, and it is written
with owner-only permissions.
"""

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

DEFAULT_BASE_URL = "http://localhost:8000/api/v1"

ENV_BASE_URL = "KERVY_BASE_URL"
ENV_TOKEN = "KERVY_API_KEY"
ENV_ORG = "KERVY_ORGANIZATION"


def config_path() -> Path:
    override = os.environ.get("KERVY_CONFIG")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "kervy-ai" / "config.json"


@dataclass
class Profile:
    base_url: str = DEFAULT_BASE_URL
    token: str | None = None
    organization_id: str | None = None

    @classmethod
    def load(cls) -> "Profile":
        stored: dict[str, str] = {}
        path = config_path()
        if path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    stored = {str(k): str(v) for k, v in loaded.items() if v is not None}
            except (OSError, ValueError):
                # A corrupt config is not worth failing on: the environment
                # can supply everything, and `login` will rewrite the file.
                stored = {}

        return cls(
            base_url=os.environ.get(ENV_BASE_URL) or stored.get("base_url") or DEFAULT_BASE_URL,
            token=os.environ.get(ENV_TOKEN) or stored.get("token"),
            organization_id=os.environ.get(ENV_ORG) or stored.get("organization_id"),
        )

    def save(self) -> Path:
        path = config_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"base_url": self.base_url}
        if self.token:
            payload["token"] = self.token
        if self.organization_id:
            payload["organization_id"] = self.organization_id
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        # Owner-only. A credential readable by every account on the machine is
        # a credential that has already leaked.
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        return path
