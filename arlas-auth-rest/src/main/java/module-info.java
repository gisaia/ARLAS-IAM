module arlas.auth.rest {
    exports io.arlas.auth.rest;
    requires java.ws.rs;
    requires swagger.annotations;
    requires org.slf4j;
    requires arlas.auth.core;
    requires dropwizard.db;
}