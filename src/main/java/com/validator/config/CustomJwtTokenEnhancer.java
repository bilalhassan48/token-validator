package com.validator.config;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.Map;

@Slf4j
public class CustomJwtTokenEnhancer extends JwtAccessTokenConverter {

    private TokenStore tokenStore;

    public CustomJwtTokenEnhancer(TokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public Map<String, Object> decode(String token) {
        log.info("decoding token");
        return super.decode(token);
    }

    public boolean validateToken(String token){
        OAuth2AccessToken oAuth2AccessToken = tokenStore.readAccessToken(token);
        return oAuth2AccessToken != null;
    }

}
