module arlas.iam.rest {
    exports io.arlas.iam.rest;
    exports io.arlas.iam.rest.service;
    exports io.arlas.iam.rest.model.input;
    exports io.arlas.iam.rest.model.output;

    requires transitive arlas.iam.core;

    requires com.codahale.metrics.annotation;
    requires com.fasterxml.jackson.annotation;
    requires com.fasterxml.jackson.databind;
    requires dropwizard.swagger;
    requires io.dropwizard.hibernate;
    requires io.dropwizard.assets;
    requires io.dropwizard.configuration;
    requires io.dropwizard.core;
    requires io.dropwizard.db;
    requires io.dropwizard.jersey;
    requires io.dropwizard.jetty;
    requires io.swagger.v3.oas.annotations;
    requires jakarta.ws.rs;
    requires jakarta.validation;
    requires jersey.media.multipart;
    requires org.eclipse.jetty.servlets;
    requires org.slf4j;
}