from fastapi import FastAPI, Query, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.responses import PlainTextResponse
import httpx
import logging
import re
import json
from urllib.parse import unquote
from datetime import datetime
from prometheus_fastapi_instrumentator import Instrumentator
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

app = FastAPI()

VICTORIALOGS_URL = "http://vmauth:9428/select/logsql/query"

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

instrumentator = Instrumentator(
        should_group_status_codes=True,
        excluded_handlers=["/metrics"],
    )

instrumentator.instrument(app).expose(app)

def convert_logql_to_logsql(query: str) -> str:
    query = unquote(query).strip()
    parts = [part.strip() for part in query.split('|')]
    label_expr = parts[0]
    pipe_parts = parts[1:] if len(parts) > 1 else []

    logsql_parts = []
    m = re.match(r'^\{(.*)\}$', label_expr)
    if m:
        label_filters = m.group(1)
        for pair in label_filters.split(','):
            if '=' in pair:
                k, v = pair.split('=', 1)
                key = k.strip()
                value = v.strip().strip('"')
                logsql_parts.append(f'{key}: "{value}"')

    for pipe in pipe_parts:
        if pipe.lower() in ['json', 'logfmt']:
            continue
        m = re.match(r'^(\w+)\s*=\s*"([^"]+)"$', pipe)
        if m:
            k, v = m.groups()
            logsql_parts.append(f'{k}: "{v}"')

    return ' and '.join(logsql_parts)

def parse_log_line(line: str):
    try:
        obj = json.loads(line)

        time_str = obj.get('_time')
        if not time_str:
            return None

        dt = datetime.strptime(time_str, "%Y-%m-%dT%H:%M:%SZ")
        ts_ns = int(dt.timestamp() * 1e9)

        cleaned_obj = {k: v for k, v in obj.items() if not k.startswith("_")}

        labels = {}
        values = {}
        top_level = {}

        for k, v in cleaned_obj.items():
            if k.startswith("labels."):
                labels[k.split(".", 1)[1]] = v
            elif k.startswith("values."):
                key = k.split(".", 1)[1]
                try:
                    values[key] = float(v) if "." in str(v) else int(v)
                except:
                    values[key] = v
            else:
                if k in {"panelID", "ruleID", "schemaVersion"}:
                    try:
                        top_level[k] = int(v)
                    except:
                        top_level[k] = v
                else:
                    top_level[k] = v

        if labels:
            top_level["labels"] = labels
        if values:
            top_level["values"] = values

        stream = {
            k.replace(".", "_"): str(v)
            for k, v in cleaned_obj.items()
            if isinstance(v, (str, int, float, bool))
        }

        message = json.dumps(top_level, ensure_ascii=False, separators=(",", ":"))

        return {
            "stream": stream,
            "values": [[str(ts_ns), message]]
        }

    except Exception as e:
        logger.warning(f"Failed to parse log line: {e}")
        return None


#@app.get("/metrics")
#def metrics():
#    return PlainTextResponse(generate_latest(), media_type=CONTENT_TYPE_LATEST)

@app.get("/loki/api/v1/query_range")
async def loki_query_range(request: Request):
    params = dict(request.query_params)
    loki_query = params.get("query", "")
    start = params.get("start")
    end = params.get("end")
    limit = params.get("limit", "100")
    logsql_query = convert_logql_to_logsql(loki_query)

    params = {
        "query": logsql_query,
        "start": start,
        "end": end,
        "limit": str(limit)
    }

    forward_headers = {}
    x_scope_org_id = request.headers.get("X-Scope-OrgID")
    if x_scope_org_id:
        forward_headers["X-Scope-OrgID"] = x_scope_org_id

    logger.info(f"Querying VictoriaLogs: {VICTORIALOGS_URL} with {params}")
    logger.info(f"With X-Scope-OrgID: {x_scope_org_id}")

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(VICTORIALOGS_URL, params=params, headers=forward_headers)
            resp.raise_for_status()
        except httpx.RequestError as e:
            raise HTTPException(status_code=502, detail=f"VictoriaLogs request failed: {str(e)}")

    lines = resp.text.strip().splitlines()
    parsed = [parse_log_line(line) for line in lines]
    parsed = [p for p in parsed if p]

    return {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": parsed
        }
    }

