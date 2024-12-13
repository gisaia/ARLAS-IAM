#!/usr/bin/env bash
set -o errexit -o pipefail

echo "=> NPM PUBLISH"

RELEASE_VERSION=$1

SCRIPT_DIRECTORY="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null && pwd)"
PROJECT_ROOT_DIRECTORY="$SCRIPT_DIRECTORY"/../..

# Update project version and build
${SCRIPT_DIRECTORY}/build_maven.sh ${RELEASE_VERSION}

echo "=> Generate API client"
ls ${PROJECT_ROOT_DIRECTORY}/tmp/

mkdir -p ${PROJECT_ROOT_DIRECTORY}/tmp/typescript-fetch
docker run --rm \
  -e GROUP_ID="$(id -g)" \
  -e USER_ID="$(id -u)" \
  --mount dst=/input/api.json,src="${PROJECT_ROOT_DIRECTORY}/tmp/openapi.json",type=bind,ro \
  --mount dst=/output,src="${PROJECT_ROOT_DIRECTORY}/tmp/typescript-fetch",type=bind \
  gisaia/swagger-codegen-3.0.42 \
  -l typescript-fetch --additional-properties modelPropertyNaming=original

echo "=> Build Typescript API "${RELEASE_VERSION}
cd ${PROJECT_ROOT_DIRECTORY}/tmp/typescript-fetch/

cp ${PROJECT_ROOT_DIRECTORY}/conf/npm/package-build.json package.json
cp ${PROJECT_ROOT_DIRECTORY}/conf/npm/tsconfig-build.json .
npm version --no-git-tag-version ${RELEASE_VERSION}
npm install
npm run build-release
npm run postbuild
cd ${PROJECT_ROOT_DIRECTORY}

echo "=> Publish Typescript API "
cp ${PROJECT_ROOT_DIRECTORY}/conf/npm/package-publish.json ${PROJECT_ROOT_DIRECTORY}/tmp/typescript-fetch/dist/package.json
cd ${PROJECT_ROOT_DIRECTORY}/tmp/typescript-fetch/dist
npm version --no-git-tag-version ${RELEASE_VERSION}

IFS='-' # - is set as delimiter
read -ra SEMVER_PARTS <<< "$RELEASE_VERSION" # $RELEASE_VERSION is read into an array as tokens separated by IFS
if [ "${#SEMVER_PARTS[@]}" -eq "1" ]; then
  # no pre-release found in semantic version => it's a release
  npm publish
else
  # pre-release found in semantic version => it's a pre-release
  npm publish --tag prerelease
fi
