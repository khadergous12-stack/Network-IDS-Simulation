# Network IDS Simulation — API Documentation

## 1. Backend

The backend is implemented using FastAPI.

Main application:

`api/main.py`

Run:

```powershell
uvicorn api.main:app --reload
```

API base address:

```text
http://127.0.0.1:8000
```

Interactive documentation:

```text
http://127.0.0.1:8000/docs
```

## 2. API Groups

The application exposes functionality for:

- Health checks
- Dashboard summary
- Network information
- Traffic analytics
- Alerts
- Incidents
- Risk distribution
- Flow submission
- Investigation/status workflow

## 3. Health

```http
GET /api/health
```

Purpose:

Confirms that the API service is responding.

## 4. Dashboard Summary

```http
GET /api/dashboard/summary
```

Purpose:

Provides high-level security/dashboard statistics.

## 5. Traffic Analytics

```http
GET /api/dashboard/traffic?limit=120
```

Purpose:

Returns traffic data used by the dashboard analytics view.

## 6. Alerts

```http
GET /api/alerts?limit=15
```

Purpose:

Retrieves alert records for the dashboard/alert queue.

## 7. Incidents

```http
GET /api/incidents?limit=15
```

Purpose:

Retrieves incident information for the analyst workflow.

## 8. Risk Distribution

```http
GET /api/risk/distribution
```

Purpose:

Provides risk/severity distribution information for dashboard visualization.

## 9. Network Sources

```http
GET /api/network/top-sources?limit=8
```

Purpose:

Provides top network sources for dashboard analytics.

## 10. Flow Submission

The application also supports submission of network-flow information through its flow-processing API.

The exact request schema should be verified from the generated OpenAPI specification at `/docs` because the implementation is the authoritative source for the current endpoint contract.

## 11. Alert Status

The analyst workflow supports status updates through the alert-status API.

The status lifecycle is:

```text
NEW
  ↓
INVESTIGATING
  ↓
RESOLVED
```

Alternative terminal classification:

```text
FALSE_POSITIVE
```

The exact request body should be taken from the current OpenAPI schema.

## 12. OpenAPI as Source of Truth

Because API schemas can change during implementation, `/openapi.json` and `/docs` should be treated as the authoritative contract when documenting or integrating against the current application.

Example:

```text
http://127.0.0.1:8000/openapi.json
```

## 13. Error Handling

API errors should be investigated using:

- HTTP status code
- response body
- Uvicorn traceback
- OpenAPI request schema
- relevant backend function

A `500 Internal Server Error` indicates an application-side exception rather than a frontend-only problem.

## 14. API Testing

FastAPI's Swagger/OpenAPI interface can be used for manual endpoint validation before automated tests are added.

Recommended checks:

1. `/api/health`
2. `/api/dashboard/summary`
3. `/api/dashboard/traffic`
4. `/api/alerts`
5. `/api/incidents`
6. `/api/risk/distribution`
7. `/api/network/top-sources`
8. Flow submission
9. Alert status workflow
