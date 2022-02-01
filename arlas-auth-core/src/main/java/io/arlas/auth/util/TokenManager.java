package io.arlas.auth.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import io.arlas.auth.core.TokenSecretDao;
import io.arlas.auth.exceptions.ArlasAuthException;
import io.arlas.auth.impl.HibernateTokenSecretDao;
import io.arlas.auth.model.LoginSession;
import io.arlas.auth.model.TokenSecret;
import org.hibernate.SessionFactory;
import org.springframework.security.crypto.keygen.KeyGenerators;

import java.util.Date;
import java.util.Optional;
import java.util.UUID;

public class TokenManager {
    private Algorithm algorithm;
    private JWTVerifier jwtVerifier;
    private final long accessTokenTTL;
    private final long refreshTokenTTL;
    private byte[] secret;
    private boolean isSecretStored = false;
    private final TokenSecretDao tokenSecretDao;

    public TokenManager(SessionFactory factory, ArlasAuthServerConfiguration configuration) {
        this.tokenSecretDao = new HibernateTokenSecretDao(factory);
        this.accessTokenTTL = configuration.accessTokenTTL;
        this.refreshTokenTTL = configuration.refreshTokenTTL;
        this.secret = KeyGenerators.secureRandom(32).generateKey();
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

    public LoginSession getLoginSession(UUID subject, String issuer, Date iat) throws ArlasAuthException {
        return new LoginSession(subject, createAccessToken(subject.toString(), issuer, iat),
                createRefreshToken(), (iat.getTime() + this.refreshTokenTTL)/1000);
    }

    private String createAccessToken(String subject, String issuer, Date iat) throws ArlasAuthException {
        try {
            storeSecret();
            Date exp = new Date(iat.getTime() + this.accessTokenTTL);
            return JWT.create()
                    .withIssuer(issuer)
                    .withSubject(subject)
                    .withIssuedAt(iat)
                    .withExpiresAt(exp)
                    .sign(this.algorithm);
        } catch (JWTCreationException exception){
            throw new ArlasAuthException("Invalid Signing configuration / Couldn't convert Claims.");
        }
    }

    private String createRefreshToken() {
        return KeyGenerators.string().generateKey();
    }
}
