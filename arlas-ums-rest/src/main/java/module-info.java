module arlas.ums.rest {
    exports io.arlas.ums.rest.model;
    exports io.arlas.ums.rest.service;
    exports io.arlas.ums.server;

    requires transitive arlas.ums.core;
    requires transitive arlas.ums.filter;

    requires com.codahale.metrics.annotation;
    requires com.fasterxml.jackson.annotation;
    requires com.fasterxml.jackson.databind;
    requires dropwizard.assets;
    requires dropwizard.configuration;
    requires dropwizard.core;
    requires dropwizard.db;
    requires dropwizard.hibernate;
    requires dropwizard.jersey;
    requires dropwizard.jetty;
    requires dropwizard.swagger;
    requires java.servlet;
    requires java.validation;
    requires java.ws.rs;
    requires jersey.media.multipart;
    requires swagger.annotations;
    requires org.eclipse.jetty.servlets;
    requires org.slf4j;
}