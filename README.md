# VulnScanner CLI

Et asynkront, letvægts CLI-værktøj til portscanning og automatisk sårbarhedsopslag (CVE).
Udviklet i Python som et praktisk værktøj til at identificere eksponerede services og deres kendte sårbarheder.

## Funktioner (Planlagte)
- **Hurtig asynkron portscanning:** Bruger Pythons `asyncio` til at scanne porte uden at blokere systemet.
- **Banner Grabbing:** Identificerer præcise service- og softwareversioner på åbne porte.
- **Automatisk CVE-opslag:** Integrerer med sårbarhedsdatabaser (NVD API) for at finde kendte sårbarheder for de fundne versioner.
- **Brugervenligt CLI:** Flot terminal-output med farvekodede tabeller via `Rich`.

## Stak
- **Sprog:** Python 3.11+
- **CLI Framework:** Typer
- **Netværk/API:** Asyncio, HTTPX
- **Datahåndtering:** Pydantic
- **Terminal UI:** Rich

## Installation
Klon projektet og opsæt dit virtuelle miljø:

```bash
git clone <dit-repo-url>
cd vuln-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Mappestruktur
```text
vuln-scanner/
├── src/
│   ├── __init__.py
│   ├── cli.py            # CLI konfiguration
│   ├── scanner.py        # Portscanning & banner grabbing
│   ├── api.py            # API kald til CVE-databaser
│   └── reporter.py       # Håndtering af output (terminal/rapporter)
├── tests/
│   └── test_scanner.py   # Unit tests
├── requirements.txt      # Afhængigheder
├── Dockerfile            # Containerisering (Kommer senere)
└── README.md             # Denne fil
```

## Brug
*(Kommandoer tilføjes, når CLI-delen er implementeret)*