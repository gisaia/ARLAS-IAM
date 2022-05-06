package io.arlas.iam.filter.impl;

import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import org.keycloak.TokenVerifier;
import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.keycloak.representations.idm.authorization.Permission;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ext.Provider;
import java.util.Collection;
import java.util.List;

@Provider
@Priority(Priorities.AUTHORIZATION)
public class KeycloakPolicyEnforcer extends AbstractPolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(KeycloakPolicyEnforcer.class);
    private AuthzClient authzClient;

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        super.setAuthConf(conf);
        this.authzClient = AuthzClient.create(new Configuration(this.authConf.keycloakConfiguration.getAuthServerUrl(),
                this.authConf.keycloakConfiguration.getRealm(), this.authConf.keycloakConfiguration.getResource(),
                this.authConf.keycloakConfiguration.getCredentials(), null)
        );
        return this;
    }

    protected Object getObjectToken(String accessToken) throws Exception {
        LOGGER.debug("accessToken (decode with https://jwt.io/)=" + accessToken);
        String token = authzClient.authorization(accessToken)
                .authorize(new AuthorizationRequest())
                .getToken();
        LOGGER.debug("RPT (decode with https://jwt.io/)=" + token);
        return TokenVerifier.create(token, AccessToken.class).getToken();
    }

    protected String getSubject(Object token) {
        return ((AccessToken)token).getSubject();
    }

    protected Collection<String> getRolesClaim(Object token) {
        return ((AccessToken)token).getResourceAccess(authConf.keycloakConfiguration.getResource()).getRoles();
    }

    protected List<String> getPermissionsClaim(Object token){
        return ((AccessToken) token).getAuthorization().getPermissions().stream()
                .map(Permission::getResourceName).toList();
    }
}
