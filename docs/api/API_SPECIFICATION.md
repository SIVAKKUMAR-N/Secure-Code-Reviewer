# NoVuln REST API Specification

The NoVuln Express API backend exposes REST endpoints for interactive code analysis, scan history retrieval, and PDF report downloads.

---

## Endpoints

### 1. Execute Code Scan
* **`POST /api/scan`**
* **Headers**: `Content-Type: application/json`
* **Request Body**:
  ```json
  {
    "code": "const query = 'SELECT * FROM users WHERE username = ' + req.query.user;",
    "language": "javascript"
  }
  ```
* **Response `200 OK`**:
  ```json
  {
    "success": true,
    "scanId": "6543210feabc",
    "summary": {
      "total": 1,
      "critical": 0,
      "high": 1,
      "medium": 0,
      "low": 0,
      "riskScore": 25,
      "riskLevel": "MEDIUM"
    },
    "vulnerabilities": [
      {
        "type": "SQL Injection",
        "severity": "High",
        "line": 1,
        "message": "Unsanitized user control flow detected in dynamic SQL query execution sink",
        "cweId": "CWE-89",
        "owaspCategory": "A03:2021 - Injection"
      }
    ]
  }
  ```

---

### 2. Download PDF Executive Report
* **`GET /api/report/:id`**
* **Response Header**: `Content-Type: application/pdf`
* **Response**: Binary PDF file stream.
