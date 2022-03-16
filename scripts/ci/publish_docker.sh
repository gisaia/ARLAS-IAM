#!/usr/bin/env bash
set -o errexit -o pipefail

echo "=> DOCKER PUSH"

RELEASE_VERSION=$1

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$SCRIPT_DIRECTORY"/../..
ARLAS_VERSION=$(mvn help:evaluate -Dexpression=arlas-commons.version -q -DforceStdout)
echo "=> ARLAS_VERSION:${ARLAS_VERSION}"
# Update project version and build
${SCRIPT_DIRECTORY}/build_maven.sh ${RELEASE_VERSION}

echo "=> Build arlas-idp-server:${RELEASE_VERSION} docker image"
docker build -t docker.cloudsmith.io/gisaia/private/arlas-idp-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile-idp .
echo "=> Build arlas-server:${RELEASE_VERSION} docker image"
docker build --build-arg TAG=${ARLAS_VERSION} -t docker.cloudsmith.io/gisaia/private/arlas-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile-arlas-server .
echo "=> Docker login cloudsmith"
echo "${DOCKER_CLOUDSMITH_PASSWORD}" | docker login docker.cloudsmith.io -u ${DOCKER_CLOUDSMITH_USERNAME} --password-stdin
echo "=> Push arlas-idp-server:${RELEASE_VERSION} docker images"
docker push docker.cloudsmith.io/gisaia/private/arlas-idp-server:${RELEASE_VERSION}
echo "=> Push arlas-server:${RELEASE_VERSION} docker images"
docker push docker.cloudsmith.io/gisaia/private/arlas-server:${RELEASE_VERSION}

IFS='-' # - is set as delimiter
read -ra SEMVER_PARTS <<< "$RELEASE_VERSION" # $RELEASE_VERSION is read into an array as tokens separated by IFS
if [ "${#SEMVER_PARTS[@]}" -eq "1" ]; then
  # no pre-release found in semantic version => it's a release
  echo "=> Tag arlas-idp-server:latest docker image"
  docker tag docker.cloudsmith.io/gisaia/private/arlas-idp-server:${RELEASE_VERSION} docker.cloudsmith.io/gisaia/private/arlas-idp-server:latest
  docker push docker.cloudsmith.io/gisaia/private/arlas-idp-server:latest
  echo "=> Tag arlas-server:latest docker image"
  docker tag docker.cloudsmith.io/gisaia/arlas-enterprise/arlas-server:${RELEASE_VERSION} docker.cloudsmith.io/gisaia/arlas-enterprise/arlas-server:latest
  docker push docker.cloudsmith.io/gisaia/arlas-enterprise/arlas-server:latest
fi