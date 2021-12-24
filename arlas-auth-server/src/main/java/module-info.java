module arlas.auth.server {
    requires org.slf4j;
    requires dropwizard.db;
    requires com.fasterxml.jackson.databind;
    requires dropwizard.configuration;
    requires dropwizard.swagger;
    requires dropwizard.assets;
    requires dropwizard.core;
    requires jersey.media.multipart;
    requires dropwizard.jersey;
    requires arlas.auth.core;
    requires arlas.auth.rest;
    requires org.eclipse.jetty.servlets;
    requires java.servlet;
    requires java.ws.rs;
    requires dropwizard.hibernate;
    requires java.validation;
    exports io.arlas.auth.server;
}