module arlas.ums.core {
    exports io.arlas.ums.core;
    exports io.arlas.ums.exceptions;
    exports io.arlas.ums.impl;
    exports io.arlas.ums.model;
    exports io.arlas.ums.util;

    requires transitive arlas.commons;
    requires transitive arlas.ums.filter;

    requires com.fasterxml.jackson.annotation;
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