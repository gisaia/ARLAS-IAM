#!/bin/bash
set -o errexit -o pipefail

function clean_docker {
  ./scripts/docker-clean.sh
  echo "===> clean maven repository"
	docker run --rm \
		-w /opt/maven \
		-v $PWD:/opt/maven \
		-v $HOME/.m2:/root/.m2 \
		maven:3.8.5-openjdk-17 \
		mvn clean
}

function clean_exit {
  ARG=$?
  echo "===> Exit status = ${ARG}"
  echo "===> arlas-iam-server logs"
  docker logs arlas-iam-server
  clean_docker
  sudo rm -rf /tmp/iam
  exit $ARG
}
trap clean_exit EXIT

# GO TO PROJECT PATH
SCRIPT_PATH=`cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd`
cd ${SCRIPT_PATH}/../..

function start_stack() {
  mkdir -p /tmp/iam
  export ARLAS_IAM_PRIVATE_ORG=true
  export ARLAS_IAM_VERIFY_EMAIL=false
  ./scripts/docker-clean.sh
  ./scripts/docker-run.sh --build --smtp4dev
}

function test_rest_server() {
    start_stack
    echo "===> run integration tests suite"
    docker run --rm \
        -w /opt/maven \
        -v $PWD:/opt/maven \
        -v $HOME/.m2:/root/.m2 \
        -e ARLAS_IAM_HOST="arlas-iam-server" \
        -e ARLAS_IAM_PREFIX="arlas_iam_server" \
        -e ARLAS_IAM_APP_PATH=${ARLAS_IAM_APP_PATH} \
        --network arlasiam_default \
        maven:3.8.5-openjdk-17 \
        mvn -Dit.test=AuthITUser verify -DskipTests=false -DfailIfNoTests=false
}

test_rest_server