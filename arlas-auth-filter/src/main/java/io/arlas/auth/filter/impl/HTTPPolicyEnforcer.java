package io.arlas.auth.filter.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.client.Client;
import javax.ws.rs.client.ClientBuilder;
import javax.ws.rs.client.Invocation;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;

@Provider
@Priority(Priorities.AUTHORIZATION)
/**
 * This is the policy enforcer to be used with Arlas Auth in Arlas Server.
 * Set ARLAS_AUTH_POLICY_CLASS=io.arlas.auth.filter.impl.HTTPPolicyEnforcer
 */
public class HTTPPolicyEnforcer extends AbstractPolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(HTTPPolicyEnforcer.class);
    private final Client client = ClientBuilder.newClient();
    private WebTarget resource;

    public HTTPPolicyEnforcer() {}

    protected HTTPPolicyEnforcer(ArlasAuthConfiguration conf) {
        this.authConf = conf;
    }

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        this.authConf = conf;
        this.resource = client.target(authConf.permissionUrl);
        return this;
    }

    @Override
    protected DecodedJWT getPermissionToken(String accessToken) throws Exception {
        Invocation.Builder request = resource.request();
        request.header(HttpHeaders.AUTHORIZATION, "bearer " + accessToken);
        request.accept(MediaType.APPLICATION_JSON);
        Response response = request.get();

        if (response.getStatusInfo().getFamily() == Response.Status.Family.SUCCESSFUL) {
            String t = response.readEntity(String.class);
            LOGGER.info("Got permission token=" + t);
            return JWT.decode(t);
        } else {
            throw new ArlasException("Impossible to get permissions with given access token:" + accessToken);
        }
    }
}
