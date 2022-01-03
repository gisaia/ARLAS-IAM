module arlas.auth.server {
    requires com.fasterxml.jackson.annotation;
    requires com.fasterxml.jackson.databind;
    requires arlas.auth.core;
    requires arlas.auth.rest;
    requires dropwizard.core;
    requires dropwizard.assets;
    requires dropwizard.configuration;
    requires dropwizard.db;
    requires dropwizard.hibernate;
    requires dropwizard.jersey;
    requires dropwizard.swagger;
    requires jersey.media.multipart;
    requires org.slf4j;
    exports io.arlas.auth.server;
}