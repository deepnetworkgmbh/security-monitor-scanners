# Security Monitor Scanners

The project is started by Deep Network GmbH on top of [Fairwinds' Polaris](https://github.com/FairwindsOps/polaris).

At the moment, it consists of three parts:

- [image-scanner](https://github.com/deepnetworkgmbh/image-scanner) - knows how to find if docker image has knows CVEs;
- [security-monitor-core](https://github.com/deepnetworkgmbh/security-monitor-core) - user-facing service. It was started from Polaris GUI;
- (this repo) [security-monitor-scanners](https://github.com/deepnetworkgmbh/security-monitor-scanners) - aggregator for misc audit/scanner types. It was started from Polaris Audit.
