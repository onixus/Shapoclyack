from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.environ.get("OCTO_API_HOST", "0.0.0.0")
    port = int(os.environ.get("OCTO_API_PORT", "8080"))
    uvicorn.run("api.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
