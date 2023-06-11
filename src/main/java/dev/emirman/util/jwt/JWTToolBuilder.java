package dev.emirman.util.jwt;

import com.auth0.jwt.algorithms.Algorithm;

public final class JWTToolBuilder {
    private String secret;
    private String issuer;
    private String[] audience;
    private Long expiration;
    private Algorithm algorithm;

    JWTToolBuilder() {
    }

    public static JWTToolBuilder newBuilder() {
        return new JWTToolBuilder();
    }

    public JWTToolBuilder withSecret(String secret) {
        this.secret = secret;
        return this;
    }

    public JWTToolBuilder withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public JWTToolBuilder withAudience(String[] audience) {
        this.audience = audience;
        return this;
    }

    public JWTToolBuilder withExpiration(Long expiration) {
        this.expiration = expiration;
        return this;
    }

    public JWTToolBuilder withAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public JWTTool build() {
        return new JWTTool(secret, issuer, audience, expiration, algorithm);
    }
}
