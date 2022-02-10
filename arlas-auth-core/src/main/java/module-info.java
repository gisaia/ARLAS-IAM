module arlas.auth.core {
    exports io.arlas.auth.core;
    exports io.arlas.auth.exceptions;
    exports io.arlas.auth.filter;
    exports io.arlas.auth.impl;
    exports io.arlas.auth.model;
    exports io.arlas.auth.util;

    requires transitive arlas.commons;
    requires arlas.auth.filter;

    requires co.elastic.apm.api;
    requires com.auth0.jwt;
    requires com.fasterxml.jackson.annotation;
    requires dropwizard.core;
    requires dropwizard.db;
    requires dropwizard.hibernate;
    requires dropwizard.jackson;
    requires dropwizard.swagger;
    requires jakarta.mail;
    requires java.persistence;
    requires java.validation;
    requires org.hibernate.orm.core;
    requires org.slf4j;
    requires spring.security.crypto;
}