module arlas.iam.core {
    exports io.arlas.iam.core;
    exports io.arlas.iam.exceptions;
    exports io.arlas.iam.impl;
    exports io.arlas.iam.model;
    exports io.arlas.iam.util;

    requires transitive arlas.commons;
    requires transitive arlas.iam.filter;

    requires com.fasterxml.jackson.annotation;
    requires dropwizard.db;
    requires dropwizard.hibernate;
    requires dropwizard.jackson;
    requires freemarker;
    requires jakarta.mail;
    requires java.annotation;
    requires java.persistence;
    requires java.validation;
    requires java.ws.rs;
    requires org.hibernate.orm.core;
    requires org.slf4j;
    requires spring.security.crypto;
}