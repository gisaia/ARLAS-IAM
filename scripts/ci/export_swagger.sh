#!/usr/bin/env bash
set -o errexit -o pipefail

RELEASE_VERSION=$1

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$SCRIPT_DIRECTORY"/../..

#########################################
#### Variables intialisation ############
#########################################
BASEDIR=$PWD
DOCKER_COMPOSE="${PROJECT_ROOT_DIRECTORY}/docker/docker-files/docker-compose.yml"
DOCKER_IP="localhost"

#########################################
#### Cleaning functions #################
#########################################
function clean_docker {
  ./scripts/docker-clean.sh
  echo "===> clean maven repository"
  docker run --rm \
    -w /opt/maven \
    -v $PWD:/opt/maven \
    -v $HOME/.m2:/root/.m2 \
    maven:3.8.4-openjdk-17 \
    mvn -q clean
}

function clean_exit {
  ARG=$?
	echo "=> Exit status = $ARG"
	clean_docker
  exit $ARG
}

function start_stack() {
    ./scripts/docker-clean.sh
    ./scripts/docker-run.sh --build
}

trap clean_exit EXIT

# Update project version and build
${SCRIPT_DIRECTORY}/build_maven.sh ${RELEASE_VERSION}

start_stack

echo "=> Get swagger documentation"
mkdir -p ${PROJECT_ROOT_DIRECTORY}/tmp || echo "${PROJECT_ROOT_DIRECTORY}/tmp exists"
i=1; until curl -XGET http://${DOCKER_IP}:9997/arlas_idp_server/swagger.json -o ${PROJECT_ROOT_DIRECTORY}/tmp/swagger.json; do if [ $i -lt 60 ]; then sleep 1; else break; fi; i=$(($i + 1)); done
i=1; until curl -XGET http://${DOCKER_IP}:9997/arlas_idp_server/swagger.yaml -o ${PROJECT_ROOT_DIRECTORY}/tmp/swagger.yaml; do if [ $i -lt 60 ]; then sleep 1; else break; fi; i=$(($i + 1)); done

echo "=> Stop arlas-idp-server stack"
docker-compose -f ${DOCKER_COMPOSE} --project-name arlasums down -v