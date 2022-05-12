#!/usr/bin/env bash
set -o errexit -o pipefail

echo "=> DOCKER PUSH"

RELEASE_VERSION=22.0.0-beta.3

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$SCRIPT_DIRECTORY"/../..

echo "=> Build arlas-server:${RELEASE_VERSION} docker image"
docker build --build-arg TAG=22.0.1-SNAPSHOT -t docker.cloudsmith.io/gisaia/private/arlas-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile-arlas-server .
echo "=> Build arlas-persistence:${RELEASE_VERSION} docker image"
docker build --build-arg TAG=22.0.1-SNAPSHOT -t docker.cloudsmith.io/gisaia/private/arlas-persistence-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile-arlas-persistence .
echo "=> Build arlas-permissions:${RELEASE_VERSION} docker image"
docker build --build-arg TAG=22.0.1-SNAPSHOT -t docker.cloudsmith.io/gisaia/private/arlas-permissions-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile-arlas-permissions .

