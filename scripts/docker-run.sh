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
  --smtp4dev)
  SMTP4DEV="-f ${PROJECT_ROOT_DIRECTORY}/docker/docker-files/dc-smtp4dev.yml"
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

export ARLAS_IAM_SERVER_VERSION=`xmlstarlet sel -t -v /_:project/_:version pom.xml`

# GO TO PROJECT PATH
SCRIPT_PATH=`cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd`
cd ${SCRIPT_PATH}/..

# PACKAGE
echo "===> compile IAM server"
docker run --rm \
    -w /opt/maven \
	-v $PWD:/opt/maven \
	-v $HOME/.m2:/root/.m2 \
	maven:3.8.5-openjdk-17 \
	mvn clean install -B -Dorg.slf4j.simpleLogger.log.org.apache.maven.cli.transfer.Slf4jMavenTransferListener=warn
echo "arlas-iam-server:${ARLAS_IAM_SERVER_VERSION}"

echo "===> start ARLAS IAM stack"
docker compose -f ${DOCKER_COMPOSE} ${SMTP4DEV} --project-name arlasiam up -d ${BUILD_OPTS}

echo "===> wait for arlas-iam-server up and running"
docker run --network arlasiam_default --rm busybox sh -c 'i=1; until nc -w 2 arlas-iam-server 9997; do if [ $i -lt 30 ]; then sleep 1; else break; fi; i=$(($i + 1)); done'
