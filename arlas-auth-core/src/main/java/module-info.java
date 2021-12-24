module arlas.auth.core {
    exports io.arlas.auth.core;
    exports io.arlas.auth.impl;
    exports io.arlas.auth.model;
    requires java.persistence;
    requires java.validation;
    requires org.hibernate.orm.core;
    requires dropwizard.hibernate;
    requires spring.security.crypto;

}