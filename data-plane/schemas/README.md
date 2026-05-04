# intellifim-schemas

Canonical event schema for IntelliFIM. Imported by every sub-project that
produces or consumes events on the `events.normalized` Kafka topic.

Install in editable mode:

    pip install -e data-plane/schemas[dev]

Run tests:

    pytest data-plane/schemas/tests
