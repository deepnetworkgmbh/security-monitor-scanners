# Roadmap

## Long-term goal

Eventually the project is going to:

- Integrates multiple *scanner/audit* types
  - Container Image vulnerabilities scanners. For example, [trivy](https://github.com/aquasecurity/trivy), [clair](https://github.com/quay/clair).
  - Kubernetes objects validators. For example, [polaris](https://github.com/FairwindsOps/polaris), [cluster-lint](https://github.com/digitalocean/clusterlint).
  - Kubernetes cluster configuration validation. For example, [kube-bench.](https://github.com/aquasecurity/kube-bench)
  - Cloud infrastructure auditors. For example, [az-sk](https://github.com/azsk/DevOpsKit), [scout-suite](https://github.com/nccgroup/ScoutSuite), [security-monkey](https://github.com/Netflix/security_monkey).
  - Web application scanners. For example, [ZAProxy](https://github.com/zaproxy/zaproxy)

- Historical data
  - Persisting all scan/audit results according to a defined retention period
  - Providing querying interface to historical data

- Supports configuration
  - enable/disable security check:
    - for the whole solution
    - for a subset of objects (tolerations) based on scanned object metadata
  - creating new security checks (maybe, [Open Policy Agent](https://www.openpolicyagent.org/) integration)

- Provides a common control-plane for all scanners types (HTTP and cli interfaces)

## Iteration 1

**The main goal**: Add new scanner/audit types.

- container-image vulnerabilities scanner [The issue #3](https://github.com/deepnetworkgmbh/security-monitor-core/issues/3):
  - `GET /api/images/` - the summary of all used docker-images vulnerabilities scans;
  - `GET /api/images/{image-tag}` - returns a single image vulnerabilities scan details.
- `polaris` audit [The issue #4](https://github.com/deepnetworkgmbh/security-monitor-core/issues/4):
  - `POST /api/kube-objects/polaris` - requests  `polaris` audit;
  - `GET /api/kube-objects/polaris` - returns the result of `polaris` audit.
- CVE [The issue #5](https://github.com/deepnetworkgmbh/security-monitor-core/issues/5):
  - `GET /api/cve/{id}` - a single CVE detailed description.
- `kube-bench` audit [The issue #6](https://github.com/deepnetworkgmbh/security-monitor-core/issues/6):
  - `POST /api/kube-cluster/bench` - requests `kube-bench` audit;
  - `GET /api/kube-cluster/bench` - returns the result of `kube-bench` audit.
- `az-sk` audit [The issue #7](https://github.com/deepnetworkgmbh/security-monitor-core/issues/7):
  - `POST /api/cloud/azure` - requests `az-sk` audit;
  - `GET /api/cloud/azure` - returns the result of `az-sk` audit.

## Iteration 2

**The main goal**: database, historical data

- store audit results in a database
- create a querying interface to historical data
