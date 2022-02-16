module arlas.auth.rest {
    exports io.arlas.auth.rest.model;
    exports io.arlas.auth.rest.service;

    requires transitive arlas.auth.core;

    requires com.codahale.metrics.annotation;
    requires dropwizard.hibernate;
    requires java.validation;
    requires java.ws.rs;
    requires org.slf4j;
    requires swagger.annotations;
}