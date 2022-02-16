#!/bin/bash
set -e

function clean_docker {
  ./scripts/docker-clean.sh
  echo "===> clean maven repository"
	docker run --rm \
		-w /opt/maven \
		-v $PWD:/opt/maven \
		-v $HOME/.m2:/root/.m2 \
		maven:3.8.4-openjdk-17 \
		mvn clean
}

function clean_exit {
  ARG=$?
	echo "===> Exit stage ${STAGE} = ${ARG}"
  clean_docker
  rm -rf /tmp/auth
  exit $ARG
}
trap clean_exit EXIT

usage(){
	echo "Usage: ./tests-integration-stage.sh --stage=REST"
	exit 1
}

for i in "$@"
do
case $i in
    --stage=*)
    STAGE="${i#*=}"
    shift # past argument=value
    ;;
    *)
            # unknown option
    ;;
esac
done

mkdir -p /tmp/auth
# GO TO PROJECT PATH
SCRIPT_PATH=`cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd`
cd ${SCRIPT_PATH}/..

if [ -z ${STAGE+x} ]; then usage; else echo "Tests stage : ${STAGE}"; fi

function start_stack() {
    ./scripts/docker-clean.sh
    ./scripts/docker-run.sh --build
}

function test_rest_server() {
    start_stack
    docker run --rm \
        -w /opt/maven \
        -v $PWD:/opt/maven \
        -v $HOME/.m2:/root/.m2 \
        -e ARLAS_AUTH_HOST="arlas-auth-server" \
        -e ARLAS_AUTH_PREFIX="arlas_auth_server" \
        -e ARLAS_AUTH_APP_PATH=${ARLAS_AUTH_APP_PATH} \
        -e ARLAS_AUTH_DATADIR="/tmp/auth" \
        --network arlasauth_default \
        maven:3.8.4-openjdk-17 \
        mvn -Dit.test=AuthIT verify -DskipTests=false -DfailIfNoTests=false
}


function test_doc() {
    ./mkDocs.sh
}

if [ ! -z ${DOCKER_USERNAME+x} ] && [ ! -z ${DOCKER_PASSWORD+x} ]
then
  echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
fi

if [ "$STAGE" == "REST_HIBERNATE" ]; then test_rest_server; fi
if [ "$STAGE" == "DOC" ]; then test_doc; fi

