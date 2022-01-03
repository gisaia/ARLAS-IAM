module arlas.auth.rest {
    exports io.arlas.auth.rest.service;
    requires java.ws.rs;
    requires swagger.annotations;
    requires org.slf4j;
    requires arlas.auth.core;
    requires dropwizard.db;
    requires com.codahale.metrics.annotation;
    requires dropwizard.hibernate;
    requires dropwizard.jackson;
    requires java.validation;
}