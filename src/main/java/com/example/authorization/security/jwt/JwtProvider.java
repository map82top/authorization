package com.example.authorization.security.jwt;

import io.jsonwebtoken.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import com.example.authorization.security.services.UserPrinciple;

import java.util.Date;

@Component
public class JwtProvider {

    private static final Logger logger = LoggerFactory.getLogger(JwtProvider.class);

    @Value("${authorization.app.jwtAccessTokenSecret}")
    private String jwtAccessTokenSecret;

    @Value("${authorization.app.jwtRefreshTokenSecret}")
    private String jwtRefreshTokenSecret;

    @Value("${authorization.app.jwtAccessTokenExpiration}")
    private int jwtAccessTokenExpiration;

    @Value("${authorization.app.jwtRefreshTokenExpiration}")
    private int jwtRefreshTokenExpiration;

    public String generateAccessJwtToken(Authentication authentication) {
        return generateJwtToken(authentication, jwtAccessTokenExpiration, jwtAccessTokenSecret);
    }

    public String generateRefreshJwtToken(Authentication authentication) {
        return generateJwtToken(authentication, jwtRefreshTokenExpiration, jwtRefreshTokenSecret);
    }

    public String generateJwtToken(Authentication authentication, int tokenExpiration, String jwtSecret) {
        UserPrinciple userPrincipal = (UserPrinciple) authentication.getPrincipal();

        return Jwts.builder()
                .setSubject(userPrincipal.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + tokenExpiration))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUserNameFromAccessJwtToken(String token) {
        return getUserNameFromJwtToken(token, jwtAccessTokenSecret);
    }

    public String getUserNameFromRefreshJwtToken(String token) {
        return getUserNameFromJwtToken(token, jwtRefreshTokenSecret);
    }

    private String getUserNameFromJwtToken(String token, String seckretKey) {
        return Jwts.parser()
                .setSigningKey(seckretKey)
                .parseClaimsJws(token)
                .getBody().getSubject();
    }

    public boolean validateAccessJwtToken(String authToken) {
        return  validateJwtToken(authToken, jwtAccessTokenSecret);
    }

    public boolean validateRefreshJwtToken(String authToken) {
        return  validateJwtToken(authToken, jwtRefreshTokenSecret);
    }

    public boolean validateJwtToken(String authToken, String jwtSecret) {
        try {
            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(authToken);
            return true;
        } catch (SignatureException e) {
            logger.error("Invalid JWT signature -> Message: {} ", e);
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token -> Message: {}", e);
        } catch (ExpiredJwtException e) {
            logger.error("Expired JWT token -> Message: {}", e);
        } catch (UnsupportedJwtException e) {
            logger.error("Unsupported JWT token -> Message: {}", e);
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty -> Message: {}", e);
        }

        return false;
    }
}