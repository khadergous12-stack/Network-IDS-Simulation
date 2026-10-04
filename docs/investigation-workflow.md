# Network IDS Simulation — Investigation Workflow

## 1. Purpose

The investigation workflow connects automated detection with analyst action.

The objective is not only to generate alerts but also to provide a structured way for an analyst to review and classify them.

## 2. Workflow

```text
Detection
   ↓
Alert
   ↓
Incident / Investigation
   ↓
NEW
   ↓
INVESTIGATING
   ↓
RESOLVED
```

Alternative:

```text
NEW
   ↓
INVESTIGATING
   ↓
FALSE_POSITIVE
```

## 3. NEW

`NEW` indicates that an alert has been generated and is awaiting analyst review.

Expected visual state:

- NEW = active
- Later stages = inactive

## 4. INVESTIGATING

`INVESTIGATING` indicates that an analyst is actively examining the event.

Expected visual state:

- NEW = completed
- INVESTIGATING = active
- RESOLVED = inactive

## 5. RESOLVED

`RESOLVED` indicates that investigation has been completed.

Expected visual state:

- NEW = completed
- INVESTIGATING = completed
- RESOLVED = active

## 6. FALSE_POSITIVE

`FALSE_POSITIVE` represents an event that was reviewed and determined not to be a meaningful security incident.

The dashboard status visualization treats the earlier workflow stages as completed without incorrectly presenting `RESOLVED` as the active state.

## 7. Analyst Review

An analyst should review:

- Source IP
- Destination IP
- Ports
- Protocol
- Flow characteristics
- Signature results
- Anomaly score
- ML score/classification
- Hybrid risk score
- Severity
- Matched rules
- Risk explanation
- Incident context

## 8. Investigation Principle

The risk score is a prioritization mechanism. It should support analyst decision-making rather than replace human review.

## 9. Validation Checklist

For every release, validate:

- Alert opens correctly.
- Status is displayed correctly.
- NEW can be represented.
- INVESTIGATING can be represented.
- RESOLVED can be represented.
- FALSE_POSITIVE can be represented.
- Status remains correct after reopening/refreshing.
- Dashboard continues to load after status changes.
- Backend and frontend remain synchronized.
