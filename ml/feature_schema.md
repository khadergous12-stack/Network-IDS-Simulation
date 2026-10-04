# ML Feature Schema

## 1. Dataset

Primary dataset:

```text
data/network_features.csv
```

Recorded shape:

```text
6,000 rows × 29 columns
```

## 2. Identifier / Context Columns

```text
flow_id
timestamp
source_ip
destination_ip
source_port
destination_port
protocol
label
scenario_type
```

These fields provide flow identity, context, or labels and should not automatically be treated as numerical ML predictors.

## 3. Raw Traffic Features

```text
packet_count
byte_count
duration_seconds
connection_count
failed_connection_count
syn_count
rst_count
average_packet_size
```

## 4. Derived Features

```text
packets_per_second
bytes_per_second
calculated_average_packet_size
connection_rate
failed_connection_ratio
syn_ratio
rst_ratio
unique_destination_ports
unique_destination_ips
unique_source_ports
source_flow_count
source_failed_flow_count
```

## 5. Feature Categories

| Category | Examples |
|---|---|
| Volume | `packet_count`, `byte_count` |
| Duration | `duration_seconds` |
| Connection behaviour | `connection_count`, `connection_rate` |
| Failure behaviour | `failed_connection_count`, `failed_connection_ratio` |
| TCP indicators | `syn_count`, `rst_count`, `syn_ratio`, `rst_ratio` |
| Packet characteristics | `average_packet_size`, `calculated_average_packet_size` |
| Rate features | `packets_per_second`, `bytes_per_second` |
| Diversity | unique ports/IPs |
| Source behaviour | source flow/failure counts |

## 6. Schema Integrity

The feature schema must remain synchronized between:

```text
Feature extraction
        ↓
ML training
        ↓
ML prediction
        ↓
Hybrid risk processing
```

A changed or missing feature can cause model-input errors or inconsistent results.

## 7. Validation

Before training/prediction, validate:

- Required columns exist.
- Numeric features contain valid numeric values.
- Missing values are handled according to the implementation.
- Label values are supported.
- Feature order matches the model's expected input.
