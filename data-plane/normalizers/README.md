# intellifim-normalizers

Per-source normalizer services. Each normalizer reads from one raw Kafka
topic, transforms events into the canonical schema from
`intellifim-schemas`, and writes to `events.normalized`.

The image is the same for all six normalizers; behaviour is selected via
the `NORMALIZER_SOURCE` environment variable (e.g. `wazuh.fim`).

Install for development:

    pip install -e data-plane/schemas
    pip install -e data-plane/normalizers[dev]

Run tests:

    pytest data-plane/normalizers/tests
