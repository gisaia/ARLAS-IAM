module arlas.auth.server {
    exports io.arlas.auth.server;

    requires arlas.auth.filter;
    requires arlas.auth.rest;

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
    requires jersey.media.multipart;
    requires org.slf4j;
    requires org.eclipse.jetty.servlets;
}