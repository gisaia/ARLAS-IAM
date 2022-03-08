package io.arlas.ums.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.arlas.commons.config.ArlasAuthConfiguration;
import io.arlas.commons.exceptions.ArlasException;
import io.arlas.ums.core.TokenSecretDao;
import io.arlas.ums.impl.HibernateTokenSecretDao;
import io.arlas.ums.model.LoginSession;
import io.arlas.ums.model.TokenSecret;
import io.arlas.ums.model.User;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.util.Date;
import java.util.Set;

public class TokenManager {
    private Algorithm algorithm;
    private JWTVerifier jwtVerifier;
    private final long accessTokenTTL;
    private final long refreshTokenTTL;
    private byte[] secret;
    private boolean isSecretStored = false;
    private final TokenSecretDao tokenSecretDao;
    private final ArlasAuthConfiguration authConf;


    public TokenManager(SessionFactory factory, ArlasAuthServerConfiguration configuration) {
        this.tokenSecretDao = new HibernateTokenSecretDao(factory);
        this.accessTokenTTL = configuration.accessTokenTTL;
        this.refreshTokenTTL = configuration.refreshTokenTTL;
        this.secret = KeyGenerators.secureRandom(32).generateKey();
        this.authConf = configuration.arlasAuthConfiguration;
    }

    private void storeSecret() {
        // we can't store the secret until an hibernate session is opened
        if (!isSecretStored) {
            // initialize secret if not existing, must be at least 256bits for HMAC256
            this.secret = tokenSecretDao.readSecret()
                    .orElseGet(() -> tokenSecretDao.createSecret(new TokenSecret(this.secret))).getSecret();
            this.algorithm = Algorithm.HMAC256(this.secret);
            this.jwtVerifier = JWT.require(this.algorithm).acceptLeeway(3).build();
            this.isSecretStored = true;
        }
    }

    public DecodedJWT verifyToken(String token) {
        storeSecret();
        return jwtVerifier.verify(token);
    }

    public LoginSession getLoginSession(User subject, String issuer, Date iat) throws ArlasException {
        return new LoginSession(subject, createAccessToken(subject, issuer, iat),
                createRefreshToken(), (iat.getTime() + this.refreshTokenTTL)/1000);
    }

    public String createPermissionToken(String subject, String issuer, Date iat, Set<String> permissions) throws ArlasException {
        try {
            storeSecret();
            Date exp = new Date(iat.getTime() + this.accessTokenTTL);
            return JWT.create()
                    .withIssuer(issuer)
                    .withSubject(subject)
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .withClaim(this.authConf.claimPermissions, permissions.stream().toList())
                    .sign(this.algorithm);
        } catch (JWTCreationException exception){
            throw new ArlasException("Invalid Signing configuration / Couldn't convert Claims.");
        }
    }

    private String createAccessToken(User subject, String issuer, Date iat) throws ArlasException {
        try {
            storeSecret();
            Date exp = new Date(iat.getTime() + this.accessTokenTTL);
            return JWT.create()
                    .withIssuer(issuer)
                    .withSubject(subject.getId().toString())
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .withClaim("locale", subject.getLocale())
                    .withClaim("timezone", subject.getTimezone())
                    .sign(this.algorithm);
        } catch (JWTCreationException exception){
            throw new ArlasException("Invalid Signing configuration / Couldn't convert Claims.");
        }
    }

    private String createRefreshToken() {
        return KeyGenerators.string().generateKey();
    }
}