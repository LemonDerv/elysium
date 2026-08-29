# Performance Policy

Any changes that touch the data plane or packet processing pipeline must be benchmarked to ensure no significant degradation in networking performance.

## Measurements

Security fixes and networking changes should be evaluated against the following metrics:
- Throughput (MB/s)
- Packets/sec
- Latency (ms)
- CPU Utilization
- Memory Footprint
- Number of Allocations per packet

Do not claim a change has "no performance impact" unless it has been explicitly benchmarked and verified.
