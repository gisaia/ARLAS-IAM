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
  echo "===> arlas-idp-server logs"
  docker logs arlas-idp-server
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
  export ARLAS_IAM_DATADIR="/tmp/iam"
  export ARLAS_IAM_VERIFY_EMAIL=false
  export ARLAS_AUTH_PUBLIC_URIS=".*"
  ./scripts/docker-clean.sh
  ./scripts/docker-run.sh --build
}

function test_rest_server() {
    start_stack
    echo "===> run integration tests suite"
    docker run --rm \
        -w /opt/maven \
        -v $PWD:/opt/maven \
        -v $HOME/.m2:/root/.m2 \
        -e ARLAS_IAM_HOST="arlas-idp-server" \
        -e ARLAS_IAM_PREFIX="arlas_idp_server" \
        -e ARLAS_IAM_APP_PATH=${ARLAS_IAM_APP_PATH} \
        -e ARLAS_IAM_DATADIR="/tmp/iam" \
        --network arlasiam_default \
        maven:3.8.5-openjdk-17 \
        mvn -Dit.test=AuthITUser verify -DskipTests=false -DfailIfNoTests=false
}

test_rest_server