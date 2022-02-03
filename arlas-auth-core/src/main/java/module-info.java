module arlas.auth.core {
    exports io.arlas.auth.core;
    exports io.arlas.auth.exceptions;
    exports io.arlas.auth.impl;
    exports io.arlas.auth.model;
    exports io.arlas.auth.util;
    exports io.arlas.auth.filter;
    requires java.persistence;
    requires org.hibernate.orm.core;
    requires dropwizard.hibernate;
    requires spring.security.crypto;
    requires dropwizard.jackson;
    requires com.fasterxml.jackson.annotation;
    requires dropwizard.core;
    requires dropwizard.db;
    requires dropwizard.swagger;
    requires java.ws.rs;
    requires org.slf4j;
    requires jakarta.mail;
    requires java.validation;
    requires com.auth0.jwt;
    requires java.annotation;
    requires co.elastic.apm.api;
}