module arlas.ums.rest {
    exports io.arlas.ums.rest.model;
    exports io.arlas.ums.rest.service;

    requires transitive arlas.ums.core;

    requires com.codahale.metrics.annotation;
    requires dropwizard.hibernate;
    requires java.validation;
    requires java.ws.rs;
    requires org.slf4j;
    requires swagger.annotations;
}