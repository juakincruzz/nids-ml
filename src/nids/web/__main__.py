"""`make web`: arranca el panel en http://127.0.0.1:8000 (host y puerto en el config)."""

import uvicorn

from nids.config import load_config
from nids.web.app import create_app


def main() -> None:
    config = load_config()
    print(
        f"Panel en http://{config['web']['host']}:{config['web']['port']}/"
        "?dia=viernes&desde=15:50&velocidad=300",
        flush=True,
    )
    uvicorn.run(create_app(config), host=config["web"]["host"], port=config["web"]["port"])


if __name__ == "__main__":
    main()
