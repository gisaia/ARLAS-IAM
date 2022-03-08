#!/bin/bash
set -e

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$(dirname "$SCRIPT_DIRECTORY")"
BUILD_OPTS="--no-build"
DOCKER_COMPOSE="${PROJECT_ROOT_DIRECTORY}/docker/docker-files/docker-compose.yml"

for i in "$@"
do
case $i in
  --build)
  BUILD_OPTS="--build"
  shift # past argument with no value
  ;;
  *)
    # unknown option
  ;;
esac
done

function clean_exit {
  ARG=$?
  exit $ARG
}
trap clean_exit EXIT

export ARLAS_UMS_SERVER_VERSION=`xmlstarlet sel -t -v /_:project/_:version pom.xml`

# GO TO PROJECT PATH
SCRIPT_PATH=`cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd`
cd ${SCRIPT_PATH}/..

# PACKAGE
echo "===> compile UMS servers"
docker run --rm \
    -w /opt/maven \
	-v $PWD:/opt/maven \
	-v $HOME/.m2:/root/.m2 \
	maven:3.8.4-openjdk-17 \
	mvn clean install -B -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn
echo "arlas-auth-server:${ARLAS_UMS_SERVER_VERSION}"
echo "arlas-idp-server:${ARLAS_UMS_SERVER_VERSION}"

echo "===> start ARLAS UMS stack"
docker-compose -f ${DOCKER_COMPOSE} --project-name arlasums up -d ${BUILD_OPTS}

echo "===> wait for arlas-auth-server up and running"
docker run --network arlasums_default --rm busybox sh -c 'i=1; until nc -w 2 arlas-auth-server 9990; do if [ $i -lt 30 ]; then sleep 1; else break; fi; i=$(($i + 1)); done'
echo "===> wait for arlas-idp-server up and running"
docker run --network arlasums_default --rm busybox sh -c 'i=1; until nc -w 2 arlas-idp-server 9991; do if [ $i -lt 30 ]; then sleep 1; else break; fi; i=$(($i + 1)); done'
