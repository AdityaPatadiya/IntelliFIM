#!/usr/bin/env bash
set -euo pipefail

KAFKA_CONTAINER="${KAFKA_CONTAINER:-kafka}"

create_topic() {
  local name=$1
  local partitions=$2
  local retention_ms=$3
  echo "creating topic ${name} (partitions=${partitions}, retention=${retention_ms}ms)"
  docker exec "${KAFKA_CONTAINER}" /opt/bitnami/kafka/bin/kafka-topics.sh \
    --bootstrap-server kafka:9092 \
    --create --if-not-exists \
    --topic "${name}" \
    --partitions "${partitions}" \
    --replication-factor 1 \
    --config "retention.ms=${retention_ms}"
}

# Per-source raw topics
create_topic wazuh.fim   3 $((7 * 24 * 60 * 60 * 1000))
create_topic wazuh.auth  3 $((7 * 24 * 60 * 60 * 1000))
create_topic zeek.conn   3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.dns    3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.http   3 $((3 * 24 * 60 * 60 * 1000))
create_topic zeek.files  3 $((7 * 24 * 60 * 60 * 1000))

# Canonical topic
create_topic events.normalized 6 $((14 * 24 * 60 * 60 * 1000))

# Correlated topic
create_topic events.correlated 6 $((14 * 24 * 60 * 60 * 1000))

# Scored topic
create_topic events.scored 6 $((14 * 24 * 60 * 60 * 1000))

echo "all topics created"
