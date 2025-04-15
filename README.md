Project for save grafana alerts history in victorialogs

for set-up grafana use this
```
    [unified_alerting.state_history]
    backend = loki
    enabled = true
    loki_remote_read_url = http://<wrapper_url>:9428
    loki_remote_write_url = http://<wrapper_url>:9428/insert
    loki_tenant_id = grafana_stage
```
