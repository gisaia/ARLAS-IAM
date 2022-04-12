package io.arlas.ums.filter.impl;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.rest.auth.PolicyEnforcer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Priority;
import javax.ws.rs.Priorities;
import javax.ws.rs.ext.Provider;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

@Provider
@Priority(Priorities.AUTHORIZATION)
/**
 * This is the policy enforcer to be used with Auth0 in Arlas Server.
 * Set ARLAS_AUTH_POLICY_CLASS=io.arlas.ums.filter.impl.Auth0PolicyEnforcer
 */
public class Auth0PolicyEnforcer extends AbstractPolicyEnforcer {
    private final Logger LOGGER = LoggerFactory.getLogger(Auth0PolicyEnforcer.class);
    private JWTVerifier jwtVerifier;

    public Auth0PolicyEnforcer() {}

    @Override
    public PolicyEnforcer setAuthConf(ArlasAuthConfiguration conf) throws Exception {
        super.setAuthConf(conf);
        this.jwtVerifier = JWT.require(Algorithm.RSA256(getPemPublicKey(), null)).acceptLeeway(3).build();
        return this;
    }

    @Override
    protected Object getObjectToken(String accessToken) {
        LOGGER.debug("accessToken (decode with https://jwt.io/)=" + accessToken);
        return jwtVerifier.verify(accessToken);
    }

    /**
     * Extract RSA public key from a PEM file containing an X.509 certificate.
     */
    private RSAPublicKey getPemPublicKey() throws Exception {
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try (InputStream is = getCertificateStream()) {
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            return (RSAPublicKey) cer.getPublicKey();
        }
    }

    private InputStream getCertificateStream() throws Exception {
        if (this.authConf.certificateUrl != null && !this.authConf.certificateUrl.isBlank()) {
            return new URL(this.authConf.certificateUrl).openStream();
        } else {
            LOGGER.warn("Configuration 'arlas_auth.certificate_file' is deprecated. Consider using 'arlas_auth.certificate_url'.");
            return new FileInputStream(this.authConf.certificateFile);
        }
    }
}
