module arlas.ums.core {
    exports io.arlas.ums.core;
    exports io.arlas.ums.exceptions;
    exports io.arlas.ums.impl;
    exports io.arlas.ums.model;
    exports io.arlas.ums.util;

    requires transitive arlas.commons;
    requires arlas.ums.filter;

    requires com.auth0.jwt;
    requires com.fasterxml.jackson.annotation;
    requires dropwizard.core;
    requires dropwizard.db;
    requires dropwizard.hibernate;
    requires dropwizard.jackson;
    requires dropwizard.swagger;
    requires jakarta.mail;
    requires java.annotation;
    requires java.persistence;
    requires java.validation;
    requires java.ws.rs;
    requires org.hibernate.orm.core;
    requires org.slf4j;
    requires spring.security.crypto;
    requires freemarker;
}