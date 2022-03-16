#!/bin/sh

fetchConfiguration(){
  echo "Downloading the ARLAS configuration file from "${ARLAS_UMS_CONFIGURATION_URL}" ..."
  curl ${ARLAS_UMS_CONFIGURATION_URL} -o /opt/app/configuration.yaml && echo "Configuration file downloaded with success." || (echo "Failed to download the configuration file. ARLAS auth server will not start."; exit 1)
}

if [ -z "${ARLAS_UMS_CONFIGURATION_URL}" ]; then
  echo "The default ARLAS IDP server container configuration file is used"
else
  fetchConfiguration;
fi

if [ -z "${ARLAS_XMX}" ]; then
  ARLAS_XMX="512m";
  echo "Default value used for ARLAS_XMX:"$ARLAS_XMX
else
  echo "ARLAS_XMX"=$ARLAS_XMX
fi

java -Xmx${ARLAS_XMX} -XX:+ExitOnOutOfMemoryError ${JVM_OPTION} -jar arlas-idp-server.jar server /opt/app/configuration.yaml
