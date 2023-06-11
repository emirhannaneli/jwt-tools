package dev.emirman.util.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import dev.emirman.util.jwt.exception.InvalidToken;
import dev.emirman.util.validator.Validator;

import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class JWTTool {
    private String secret;
    private String issuer;
    private String[] audience;
    private Long expiration;
    private Algorithm algorithm;
    private Validator validator;

    public JWTTool() {
    }

    public JWTTool(String secret, String issuer, String[] audience, Long expiration, Algorithm algorithm) {
        this.secret = secret;
        this.issuer = issuer;
        this.audience = audience;
        this.expiration = expiration;
        this.algorithm = algorithm;
    }

    public static JWTToolBuilder builder() {
        return new JWTToolBuilder();
    }

    public String secret() {
        return secret;
    }

    public JWTTool withSecret(String secret) {
        this.secret = secret;
        return this;
    }

    public String issuer() {
        return issuer;
    }

    public JWTTool withIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public String[] audience() {
        return audience;
    }

    public JWTTool withAudience(String[] audience) {
        this.audience = audience;
        return this;
    }

    public Long expiration() {
        return expiration;
    }

    public JWTTool withExpiration(Long expiration) {
        this.expiration = expiration;
        return this;
    }

    public Algorithm algorithm() {
        return algorithm;
    }

    public JWTTool withAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public Validator validator() {
        return validator;
    }

    public JWTTool withValidator(Validator validator) {
        this.validator = validator;
        return this;
    }

    public DecodedJWT decodedJWTFromToken(String token) {
        if (validator == null) validator = new Validator();
        boolean isValidToken = validator.isValidString(token);
        if (!isValidToken) throw new InvalidToken();
        try {
            JWTVerifier verifier = JWT.require(algorithm).build();
            return verifier.verify(token);
        } catch (Exception e) {
            throw new InvalidToken();
        }
    }

    public <T> T claimFromToken(String token, String claim, Class<T> type) {
        DecodedJWT decodedJWT = decodedJWTFromToken(token);
        return decodedJWT.getClaim(claim).as(type);
    }

    public <T> T subjectFromToken(String token, Class<T> type) {
        return claimFromToken(token, "sub", type);
    }

    public Object subjectFromToken(String token) {
        DecodedJWT decodedJWT = decodedJWTFromToken(token);
        return decodedJWT.getSubject();
    }

    public boolean isTokenExpired(String token) {
        DecodedJWT decodedJWT = decodedJWTFromToken(token);
        return decodedJWT.getExpiresAt().before(new Date());
    }

    public boolean isValidToken(String token) {
        DecodedJWT decodedJWT = decodedJWTFromToken(token);
        boolean expired = isTokenExpired(token);
        boolean issuer = decodedJWT.getIssuer().equals(issuer());
        boolean audience =  Arrays.stream(audience())
                .anyMatch(s -> decodedJWT.getAudience().contains(s));
        return !expired && issuer && audience;
    }

    public String generateToken(String subject, Long expiration, String... claims) {
        if (validator == null) validator = new Validator();
        List<String> claimsList = Arrays.stream(claims).toList();
        boolean isValidSubject = validator.isValidString(subject);
        boolean isValidClaims = validator.isValidList(claimsList);
        if (!isValidSubject || !isValidClaims) throw new IllegalArgumentException();
        return JWT.create()
                .withSubject(subject)
                .withIssuer(issuer)
                .withAudience(audience)
                .withExpiresAt(new Date(System.currentTimeMillis() + expiration))
                .withArrayClaim("claims", claims)
                .sign(algorithm);
    }

    public String generateToken(String subject, String... claims) {
        return generateToken(subject, expiration(), claims);
    }
}
