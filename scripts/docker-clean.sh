#!/bin/bash
set -e

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$(dirname "$SCRIPT_DIRECTORY")"
DOCKER_COMPOSE="${PROJECT_ROOT_DIRECTORY}/docker/docker-files/docker-compose.yml"

function clean_exit {
  ARG=$?
  exit $ARG
}
trap clean_exit EXIT

echo "===> stop arlas IAM stack"
docker-compose -f ${DOCKER_COMPOSE} --project-name arlasiam down -v --remove-orphans