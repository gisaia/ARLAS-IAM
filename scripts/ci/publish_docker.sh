#!/usr/bin/env bash
set -o errexit -o pipefail

echo "=> DOCKER PUSH"

RELEASE_VERSION=$1

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$SCRIPT_DIRECTORY"/../..
echo "=> ARLAS_VERSION:${ARLAS_VERSION}"
# Update project version and build
${SCRIPT_DIRECTORY}/build_maven.sh ${RELEASE_VERSION}

echo "=> Build arlas-iam-server:${RELEASE_VERSION} docker image"
docker build -t gisaia/arlas-iam-server:${RELEASE_VERSION} -f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/Dockerfile .

echo "=> Push arlas-iam-server:${RELEASE_VERSION} docker images"
docker push gisaia/arlas-iam-server:${RELEASE_VERSION}

IFS='-' # - is set as delimiter
read -ra SEMVER_PARTS <<< "$RELEASE_VERSION" # $RELEASE_VERSION is read into an array as tokens separated by IFS
if [ "${#SEMVER_PARTS[@]}" -eq "1" ]; then
  # no pre-release found in semantic version => it's a release
  echo "=> Tag arlas-iam-server:latest docker image"
  docker tag gisaia/arlas-iam-server:${RELEASE_VERSION} gisaia/arlas-iam-server:latest
  docker push gisaia/arlas-iam-server:latest
fi
