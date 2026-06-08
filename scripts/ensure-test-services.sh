#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ]; then
  echo "usage: $0 <docker-compose-service>..." >&2
  exit 2
fi

compose_project="openauth"

container_name_for() {
  case "$1" in
    postgres) echo "openauth-postgres" ;;
    mysql) echo "openauth-mysql" ;;
    redis) echo "openauth-redis" ;;
    valkey) echo "openauth-valkey" ;;
    *)
      echo "unknown test service: $1" >&2
      exit 2
      ;;
  esac
}

container_port_for() {
  case "$1" in
    postgres) echo "5432/tcp" ;;
    mysql) echo "3306/tcp" ;;
    redis | valkey) echo "6379/tcp" ;;
  esac
}

remove_foreign_container() {
  local service="$1"
  local container
  local project
  local compose_service

  container="$(container_name_for "$service")"

  if ! docker inspect "$container" >/dev/null 2>&1; then
    return 0
  fi

  project="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.project" }}' "$container" 2>/dev/null || true)"
  compose_service="$(docker inspect -f '{{ index .Config.Labels "com.docker.compose.service" }}' "$container" 2>/dev/null || true)"

  if [ "$project" != "$compose_project" ] || [ "$compose_service" != "$service" ]; then
    echo "Removing stale test container $container"
    docker rm -f "$container" >/dev/null
  fi
}

assert_published_port() {
  local service="$1"
  local container
  local container_port
  local host_port

  container="$(container_name_for "$service")"
  container_port="$(container_port_for "$service")"
  host_port="$(docker inspect -f "{{ with index .NetworkSettings.Ports \"$container_port\" }}{{ (index . 0).HostPort }}{{ end }}" "$container" 2>/dev/null || true)"

  if [ -z "$host_port" ]; then
    echo "$container is running without published port $container_port" >&2
    exit 1
  fi
}

for service in "$@"; do
  remove_foreign_container "$service"
done

compose_up_with_retry() {
  local attempt=1
  local max_attempts=3
  local delay_seconds=5

  while true; do
    if docker compose up -d --force-recreate --remove-orphans --wait "$@"; then
      return 0
    fi

    if [ "$attempt" -ge "$max_attempts" ]; then
      echo "docker compose up failed after $max_attempts attempts" >&2
      return 1
    fi

    echo "docker compose up failed (attempt $attempt/$max_attempts); retrying in ${delay_seconds}s..." >&2
    attempt=$((attempt + 1))
    sleep "$delay_seconds"
    delay_seconds=$((delay_seconds * 2))
  done
}

compose_up_with_retry "$@"

for service in "$@"; do
  assert_published_port "$service"
done

docker compose ps "$@"
