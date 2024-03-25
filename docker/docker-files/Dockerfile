#####################
# COMPILATION STAGE #
#####################
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /opt/build

# selectively add the POM file
ADD pom.xml /opt/build/
# get all the downloads out of the way
RUN mvn verify clean --fail-never

# build all project
COPY . /opt/build/
RUN mvn install \
    && mv /opt/build/arlas-iam-server/target/arlas-iam-server-*.jar /opt/build/arlas-iam-server.jar

###################
# PACKAGING STAGE #
###################
FROM gisaia/arlas-openjdk-17-distroless:20240325094836

# application placed into /opt/app
WORKDIR /opt/app
COPY --from=build /opt/build/arlas-iam-server.jar /opt/app/
COPY --from=build /opt/build/conf/configuration.yaml /opt/app/
COPY --from=build /opt/build/arlas-iam-core/src/main/resources/templates/*.ftlh /opt/app/
EXPOSE 9997

ENV JDK_JAVA_OPTIONS="-Xmx512m -XX:+ExitOnOutOfMemoryError"
CMD ["arlas-iam-server.jar", "server", "/opt/app/configuration.yaml"]