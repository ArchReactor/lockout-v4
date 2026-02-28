# Data Dictionary - AR Lockout Project

This document defines the primary data fields used across the AR Lockout system, covering device configuration, CiviCRM integration, and environment settings.

---

## 1. Lockout Device Configuration (`lockouts.csv`)

This file (located in `web/lockouts.csv`) defines the physical hardware managed by the system.

| Field Name | C++ Size | API Source Size | Description | Example / Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Name** | N/A | N/A | Display name of the lockout device. | `Front Door`, `Table Saw` |
| **IP Address** | N/A | N/A | Static IP or hostname of the ESP32/ESP8266 device. | `192.168.1.50` |
| **Groups** | `char[10]` | N/A | Comma-separated list of CiviCRM Group IDs authorized for this device. | `12,45` (Buffer limit: 9 chars) |
| **Timeout** | N/A | N/A | Seconds the device stays active after a valid scan. | `5` (99999 = toggle/reset mode) |

---

## 2. CiviCRM Contact Fields

Data retrieved from CiviCRM via `fetch.php` for local caching on devices.

| Field Name | C++ Size | API Source Size | Source Key | Description |
| :--- | :--- | :--- | :--- | :--- |
| **Contact ID** | `int` (4b) | `int` (32-bit) | `id` | Unique internal CiviCRM identifier for the member. |
| **Display Name** | `char[40]` | `varchar(128)` | `display_name` | The full name of the member. (Truncated if > 39 chars) |
| **RFID Card ID** | `char[40]` | `varchar(255)` | `Card_ID.new_card_id` | The unique hex/dec string from the member's RFID tag. |

---

## 3. CiviCRM Activity Fields (Logging)

Fields used when pushing access events back to CiviCRM via `rfid.php` or `rfid-fail.php`.

| Field Name | C++ Size | API Source Size | Description | Values / Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Source Contact** | N/A | `int` | The contact originating the event. | Member ID (Success) or System Owner (Fail) |
| **Activity Type** | N/A | `int` | Categorizes the event in CiviCRM. | Defined by `CIVICRM_RFID_ACTVITY` |
| **Status** | N/A | `int` | The outcome of the access attempt. | `2` (Success), `3` (Fail/Denied) |
| **Subject** | N/A | `varchar(255)` | Brief summary of the event. | Truncated to 255 chars in CiviCRM. |
| **Timestamp** | N/A | `datetime` | When the event occurred. | Format: `Y-m-d H:i:s` |
| **Assignee** | N/A | `int` | The member associated with the event. | `id` of the scanned card |

---

## 4. System Environment Variables (`.env`)

Global configuration for API connectivity and system defaults.

| Variable | C++ Size | API Source Size | Description | notes |
| :--- | :--- | :--- | :--- | :--- |
| `CIVICRM_WEBSITE` | N/A | N/A | Base URL of the CiviCRM installation. | |
| `CIVICRM_AUTH` | N/A | N/A | CiviCRM API v4 Bearer Token. | Found in User Profile > API Key |
| `CIVICRM_KEY` | N/A | N/A | CiviCRM Site Key. | Found in site config |
| `CIVICRM_APIv4URI` | N/A | N/A | Endpoint for API v4 calls. | Usually `/civicrm/ajax/api4` |
| `CIVICRM_RFID_ACTVITY`| N/A | `int` | Activity Type ID for RFID logs. | |
| `CIVICRM_RFID_OWNER` | N/A | `int` | Contact ID for system-level fail logging. | Admin/System User ID |
| `ESPHOME_USER` | N/A | N/A | Dashboard and device login username. | |
| `ESPHOME_PASSWORD` | N/A | N/A | Dashboard and device login password. | |
| `TZ` | N/A | N/A | System timezone. | `America/Chicago` |
