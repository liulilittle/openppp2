# Offline policy benchmark

`policy_offline_benchmark.cpp` measures generated exact-domain and IPv4 `/32`
policy rules through the production source loader, compiler, runtime, and
evaluator. It does not start the PPP client, open network connections, or
change routes or DNS settings. The resolver cache is covered separately by
`policy_dns_transport_test`, which uses an injected fake exchange and clock.

The benchmarks are optional standalone targets and are not registered with
CTest. Configure and build them with:

```sh
cmake -S tests/cpp -B build/private/dns-policy-p5-benchmarks -G Ninja \
  -DCMAKE_BUILD_TYPE=Release -DENABLE_POLICY_BENCHMARKS=ON
cmake --build build/private/dns-policy-p5-benchmarks --parallel 2 \
  --target policy_offline_benchmark policy_dns_cache_benchmark
```

They use the repository's offline policy core and the resolver test's fake
network guards. The build requires the same Boost and OpenSSL dependencies as
the C++ policy tests. Both executables write JSON to stdout unless `--output`
is given.

Run each scale in a separate process so `peak_rss_bytes` is attributable to
that run. Keep reports under the ignored private build area:

```sh
mkdir -p build/private/policy-benchmark
./build/private/dns-policy-p5-benchmarks/policy_offline_benchmark --scale small \
  --output build/private/policy-benchmark/small.json
./build/private/dns-policy-p5-benchmarks/policy_offline_benchmark --scale 100k \
  --output build/private/policy-benchmark/100k.json
./build/private/dns-policy-p5-benchmarks/policy_offline_benchmark --scale 1m \
  --output build/private/policy-benchmark/1m.json
```

The default fixed seed is `7121407`; use `--seed N` to select another
deterministic dataset. `--samples N` controls domain/IP and bounded regex
evaluation samples. `--rules N` selects a custom rule count and reports the
scale as `custom`. The JSON contains the environment/build mode, rule counts,
loader and compile times, domain/IP hit and miss p50/p95/p99 in nanoseconds,
regex growth at 0/5/20/50 rules, reader latency during candidate preparation
and commit, and peak RSS. Linux reports `getrusage.ru_maxrss` converted to
bytes; unsupported platforms report zero. There are no machine-speed pass
thresholds, and Debug and Release results should be compared separately.

Temporary rule files are created outside the repository and removed after
each run. Use the benchmark only for local performance evidence; it does not
measure DNS transport latency or claim real-session throughput.

## Resolver cache benchmark

`policy_dns_cache_benchmark.cpp` uses the production `PolicyResolverService`
with a fake callback transport, an inert session transport, and a fixed
injected clock. Each unique cold miss is followed immediately by a warm hit
for that key, so samples remain valid even when the total exceeds cache
capacity. The report includes sample count, working-set size, and cache entry
capacity, and checks that fake upstream calls and service telemetry match the
sample counts. It never opens a socket. Build it as an optional standalone
target with the same resolver sources and stubs as
`policy_dns_transport_test`; it is not a CTest target.

```sh
./build/private/dns-policy-p5-benchmarks/policy_dns_cache_benchmark --samples 5000 \
  --output build/private/policy-benchmark/dns-cache.json
```

The report includes p50/p95/p99 hit and miss latency in nanoseconds, cache
hit/miss calls, and fake upstream exchange calls. These measurements isolate
the service/cache code and do not estimate real DNS network latency.
