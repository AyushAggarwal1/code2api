# code2api
Discovering APIs from source code

## Features

- Detects internal API routes (path, method, handler, path params)
- Detects external HTTP calls (URLs your code calls out to)
- Identifies auth requirements (JWT, OAuth, API Key, Basic Auth)
- Outputs structured JSON for easy integration with other tools
- Skips noise: `node_modules`, `vendor`, `.venv`, `dist`, `build`, migrations, test data, etc.

## Supported Languages & Frameworks

| Language | Frameworks |
|----------|-----------|
| **Python** | Flask, Django, FastAPI, Tornado, Bottle, Falcon, aiohttp, Sanic, Pyramid |
| **Go** | Gin, Echo, Fiber, Chi, Revel, GoKit, stdlib `net/http`, gorilla/mux |
| **JavaScript / TypeScript** | Express, Koa, NestJS, Hapi, Sails, LoopBack, Next.js |
| **Java** | Spring (all mapping annotations), JAX-RS, Micronaut, Vert.x, Play |

## Build

```bash
go build -o code2api .
```

Requires Go 1.18+.

## Usage

```bash
# Scan current directory, print JSON to stdout
./code2api -path .

# Scan a specific project, write results to file
./code2api -path /path/to/project -output result.json

# Verbose mode (shows parse warnings)
./code2api -path /path/to/project -output result.json -verbose
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-path` | `.` | Directory to scan |
| `-output` | *(stdout)* | Output JSON file path |
| `-verbose` | `false` | Print parse warnings |

## Output Format

```json
{
  "scanned_at": "2026-06-03T05:38:31Z",
  "scanned_path": "/path/to/project",
  "summary": {
    "total_internal_apis": 12,
    "total_external_apis": 3,
    "files_scanned": 8,
    "by_framework": { "FastAPI": 7, "Flask": 5 },
    "by_method": { "GET": 8, "POST": 4 }
  },
  "internal_apis": [
    {
      "file": "app/routes.py",
      "framework": "FastAPI",
      "method": "GET",
      "path": "/users/{user_id}",
      "full_path": "/users/{user_id}",
      "handler": "get_user",
      "path_params": ["user_id"],
      "auth_required": true,
      "auth_type": "JWT",
      "line": 42
    }
  ],
  "external_apis": [
    {
      "file": "app/client.py",
      "url": "https://api.example.com/v1/data",
      "method": "GET",
      "line": 17
    }
  ]
}
```

## Path Parameter Formats

Recognized across all supported frameworks:

| Syntax | Frameworks |
|--------|-----------|
| `:param` | Express, Gin, Chi |
| `{param}` / `{param:type}` | FastAPI, Spring |
| `<param>` / `<type:param>` | Flask |
