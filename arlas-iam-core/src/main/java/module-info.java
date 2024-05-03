module arlas.iam.core {
    exports io.arlas.iam.core;
    exports io.arlas.iam.exceptions;
    exports io.arlas.iam.impl;
    exports io.arlas.iam.model;
    exports io.arlas.iam.util;

    requires transitive arlas.commons;

    requires arlas.server.client;
    requires com.auth0.jwt;
    requires com.fasterxml.jackson.annotation;
    requires freemarker;
    requires io.dropwizard.db;
    requires io.dropwizard.hibernate;
    requires io.dropwizard.jackson;
    requires jakarta.mail;
    requires jakarta.annotation;
    requires jakarta.persistence;
    requires jakarta.validation;
    requires jakarta.ws.rs;
    requires org.hibernate.orm.core;
    requires org.slf4j;
    requires spring.security.crypto;
}