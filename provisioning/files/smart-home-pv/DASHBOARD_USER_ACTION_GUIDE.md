# Dashboard User Action Guide

## Purpose

This guide explains how to use the admin dashboard activity log to document **green-team user actions** during the Smart Home PV cyber range. It is based on the real log format currently written to:

- `/home/whitefalcon/smart-home-pv-logs/admin_dashboard_actions.log`

The objective is not to log the attacker directly. The objective is to log what the **dashboard operator** did in response to suspicious activity:

- what page they opened
- what button they clicked
- whether they reviewed diagnostics
- whether they acknowledged an alert
- whether they documented the incident

## Log Record Format

Each line in the `.log` file is written in this structure:

```text
timestamp | actor=<user> | event_type=<type> | action=<action> | page=<page> | target=<target> | details={<json>}
```

### Fields

| Field | Meaning |
|---|---|
| `event_type` | The category of the user interaction |
| `action` | The specific activity performed |
| `target` | The UI element, section, or workflow target |
| `details` | Supporting context such as destination view, outcome, count, status, or notes |

## Recommended Event Categories

Use the following categories when reviewing or reporting user actions:

| Event type | Meaning |
|---|---|
| `Submit` | The user submitted a form or workflow |
| `Page_view` | The user opened a page or dashboard section |
| `Click` | The user clicked a control or button |
| `Security` | The user took a security response action |
| `Navigation` | The user switched between dashboard views |
| `Diagnostics` | The user reviewed or exported logs |

Note: The current implementation also records lower-level categories such as `change`, `authentication`, and `system`. For reporting, you can normalize them into the categories above. For example:

- `authentication` can be reported under `Submit`
- `system` can be reported as supporting platform context
- `change` can be treated as user preparation before `Submit`

## Observed Actions From Real Logs

The current log file already shows these green-team actions:

| Event type | Action | Target | What it means |
|---|---|---|---|
| `page_view` | `page_view` | `page=login` | User opened the login page |
| `submit` | `login_form_submitted` | `login-form` | User submitted the login form |
| `authentication` | `login_failed` | `login-form` | User attempted login but credentials failed |
| `authentication` | `login_success` | `login-form` | User successfully authenticated |
| `click` | `security_alerts_clicked` | `button.nav-item` | User opened the Security Alerts view |
| `navigation` | `dashboard_view_changed` | `sidebar-navigation` | User switched sections inside the dashboard |
| `page_view` | `page_view` | `page=dashboard/security` | User arrived at the Security Alerts page |
| `click` | `acknowledge_clicked` | `button.btn-acknowledge` | User started alert acknowledgement |
| `security` | `security_alert_acknowledged` | `alert-acknowledgement` | User confirmed an alert and recorded remediation notes |
| `diagnostics` | `diagnostics_logs_refreshed` | `admin-dashboard-actions-log` | User refreshed the diagnostics action log |
| `click` | `system_overview_clicked` | `button.nav-item` | User returned to the overview page |

## Example Interpretations From The Current Log

### 1. Authentication and Access

```text
event_type=submit | action=login_form_submitted | target=login-form
event_type=authentication | action=login_failed | target=login-form
event_type=authentication | action=login_success | target=login-form
```

Interpretation:

- The user attempted to access the dashboard
- The first attempts failed
- A later attempt succeeded
- This can indicate normal operator access, password correction, or possible brute-force observation if repeated excessively

### 2. Security Review Workflow

```text
event_type=click | action=security_alerts_clicked
event_type=navigation | action=dashboard_view_changed | details={"destination": "security"}
event_type=page_view | action=page_view | page=dashboard/security
```

Interpretation:

- The user deliberately moved into the Security Alerts workflow
- This is a good green-team response when suspicious behaviour is suspected

### 3. Incident Handling Workflow

```text
event_type=click | action=acknowledge_clicked
event_type=security | action=security_alert_acknowledged | details={"notes_present": "true", "outcome": "success"}
```

Interpretation:

- The user did not just view the incident
- The user actively documented and acknowledged it
- This is the strongest indicator that the operator responded correctly

### 4. Diagnostics Verification Workflow

```text
event_type=diagnostics | action=diagnostics_logs_refreshed | target=admin-dashboard-actions-log
```

Interpretation:

- The user reviewed the activity timeline and supporting evidence
- This should be treated as a reporting or validation step during incident handling

## Storyline-To-Action Mapping

Use the following mapping when grading or documenting operator behaviour.

| Storyline | Event | Expected green-team user action | Log evidence to look for | Expected response |
|---|---|---|---|---|
| Common (All) | Network Reconnaissance | Open dashboard and monitor overview and security pages for anomalies | `page_view`, `security_alerts_clicked`, `dashboard_view_changed`, `page=dashboard/security` | User actively monitored the platform |
| 1.0 (Modbus) | Field Modification | Switch to Security Alerts, review suspicious behaviour, then review Diagnostics | `security_alerts_clicked`, `dashboard_view_changed`, `diagnostics_clicked`, `diagnostics_logs_refreshed` | User investigated possible unauthorized field manipulation |
| 1.0 (Modbus) | Control Injection | Review alert, acknowledge incident, add notes | `acknowledge_clicked`, `security_alert_acknowledged` | User reported or documented the incident correctly |
| 2.1 (MQTT) | Topic Discovery | Monitor dashboard for unusual telemetry changes and inspect alerts | `page_view`, `security_alerts_clicked`, `dashboard_view_changed` | User recognized unusual platform behaviour |
| 2.1 (MQTT) | Telemetry Poisoning | Review Security Alerts and Diagnostics, then acknowledge | `security_alerts_clicked`, `diagnostics_logs_refreshed`, `security_alert_acknowledged` | User validated anomalous telemetry and documented it |
| 2.2 (Brute Force) | Auth Calibration | Watch for repeated failed authentication patterns in Diagnostics and Security views | `login_failed`, `security_alerts_clicked`, `diagnostics_logs_refreshed` | User observed and investigated credential attacks |
| 2.2 (Brute Force) | Credential Spraying | Confirm suspicious pattern, document or acknowledge alert | `login_failed`, `acknowledge_clicked`, `security_alert_acknowledged` | User escalated or reported repeated unauthorized access attempts |
| 2.3 (Phishing) | Server Setup | Stay on dashboard, review notification carefully, do not follow malicious lure | `page_view`, `security_alerts_clicked`, absence of suspicious external-follow action | User monitored the dashboard and avoided unsafe interaction |
| 2.3 (Phishing) | Payload Delivery | Report the incident and preserve evidence in logs | `security_alert_acknowledged`, `diagnostics_logs_refreshed`, optional export action | User created a defensible response trail |

## Minimal green-Team Response Sequence

For any suspicious scenario, the recommended operator workflow is:

1. Open the dashboard successfully.
2. Move to `Security Alerts`.
3. Review the current alert or anomaly.
4. Switch to `Diagnostics` and refresh the logs.
5. Return to the relevant page if needed.
6. Acknowledge the alert and add notes.

This workflow should produce a sequence similar to:

```text
login_success
security_alerts_clicked
dashboard_view_changed
page_view page=dashboard/security
diagnostics_clicked
dashboard_view_changed
page_view page=dashboard/diagnostics
diagnostics_logs_refreshed
acknowledge_clicked
security_alert_acknowledged
```

## How To Use The Log During Exercises

### For instructors

Use the log to verify whether the student actually performed the expected monitoring and reporting steps.

Look for:

- navigation into the correct dashboard area
- review of diagnostics evidence
- acknowledgement of the alert
- notes present during acknowledgement

### For students

Use the log as your activity trail.

If you want to prove you responded properly to an incident, make sure your session contains:

- at least one `page_view` for the relevant dashboard page
- at least one `dashboard_view_changed`
- at least one `diagnostics_logs_refreshed`
- at least one `security_alert_acknowledged`

## Reporting Template

Use this structure when summarizing a user session:

| Time | Event type | Action | Target | Interpretation |
|---|---|---|---|---|
| 14:01:28 | Page_view | `page_view` | `dashboard/overview` | User entered dashboard after login |
| 14:01:51 | Click | `security_alerts_clicked` | `button.nav-item` | User opened Security Alerts |
| 14:01:51 | Navigation | `dashboard_view_changed` | `sidebar-navigation` | User switched to security monitoring |
| 14:02:15 | Diagnostics | `diagnostics_logs_refreshed` | `admin-dashboard-actions-log` | User reviewed supporting log evidence |
| 14:02:09 | Security | `security_alert_acknowledged` | `alert-acknowledgement` | User documented and confirmed the incident |

## Analyst Notes

- `page_view` shows what the operator actually opened.
- `dashboard_view_changed` shows intent to investigate a specific area.
- `diagnostics_logs_refreshed` is strong evidence of review and evidence collection.
- `security_alert_acknowledged` is strong evidence of defensive action.
- Repeated `login_failed` before `login_success` can be legitimate or suspicious depending on context.
- If a phishing scenario is being evaluated, treat safe non-interaction plus continued dashboard monitoring as the correct behaviour.

## Recommendation

For grading and exercise review, treat the following as the core defensive evidence set:

- `page_view`
- `dashboard_view_changed`
- `security_alerts_clicked`
- `system_overview_clicked`
- `diagnostics_logs_refreshed`
- `security_alert_acknowledged`

These actions are already present in the current real log output and are sufficient to build a reliable green-team user action timeline.