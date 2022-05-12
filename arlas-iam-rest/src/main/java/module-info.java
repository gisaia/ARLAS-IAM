module arlas.iam.rest {
    exports io.arlas.iam.rest;
    exports io.arlas.iam.rest.service;
    exports io.arlas.iam.rest.model.input;
    exports io.arlas.iam.rest.model.output;

    requires transitive arlas.iam.core;
    requires transitive arlas.iam.filter;

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
    requires dropwizard.servlets;
    requires dropwizard.swagger;
    requires java.servlet;
    requires java.validation;
    requires java.ws.rs;
    requires jersey.media.multipart;
    requires swagger.annotations;
    requires org.eclipse.jetty.servlets;
    requires org.slf4j;
    requires zipkin.core;
}