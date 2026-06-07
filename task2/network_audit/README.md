# Network Audit Flask Platform

Multi-vendor network config parser, validator, and analytics dashboard.

## Features

- **Upload** Cisco (.cfg), Huawei (.cfg), Juniper (.conf) configs via drag-and-drop
- **Parse** hostname, interfaces/IPs, OSPF/BGP protocols, ACL/security rules
- **Validate**:
  - Each device has a Loopback0 interface
  - IP subnets are unique across devices (overlap detection)
  - OSPF area consistency
  - Results stored in SQLite
- **Dashboard**:
  - Validation summary table with per-device pass/fail details
  - Pie chart: BGP vs OSPF router count
  - Bar chart: interfaces per device
  - Export to CSV or Excel

## Quick Start

```bash
pip install flask flask-sqlalchemy openpyxl
python app.py
```

Then open http://localhost:5000

## Routes

| Route | Description |
|-------|-------------|
| `GET /upload` | Upload form |
| `POST /upload` | Upload + parse + validate |
| `GET /dashboard` | Analytics dashboard |
| `GET /export/csv` | Download CSV |
| `GET /export/excel` | Download Excel |
| `GET /api/devices` | JSON API |

## Sample Files

The `uploads/` folder contains the 5 sample configs:
- R1_Cisco.cfg — Cisco, OSPF
- R2_Huawei.cfg — Huawei, OSPF
- R3_Juniper.conf — Juniper, BGP
- R4_Cisco.cfg — Cisco, BGP
- R5_Huawei.cfg — Huawei

![Project overview](images/1.peg)

