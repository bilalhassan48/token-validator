package com.validator.config;

import com.validator.auth.TokenAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Autowired
    private ApplicationProperty applicationProperty;

    @Override
    public void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.csrf().disable();
        httpSecurity
            .authorizeRequests()
                .antMatchers(applicationProperty.getPublicUrlPath()).permitAll()
                .anyRequest().authenticated().and().sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
                .addFilterBefore(new TokenAuthenticationFilter(jwtAccessTokenConvert(), applicationProperty), UsernamePasswordAuthenticationFilter.class)
            .exceptionHandling()
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.sendError(HttpServletResponse.SC_FORBIDDEN);
                })
                .authenticationEntryPoint((request, response, authException) -> {
                    response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                });
    }

    @Bean
    public CustomJwtTokenEnhancer jwtAccessTokenConvert() {
        CustomJwtTokenEnhancer jwtAccessTokenConverter = new CustomJwtTokenEnhancer(tokenStore());
        jwtAccessTokenConverter.setSigningKey(applicationProperty.getSigningKey());
        jwtAccessTokenConverter.setJwtClaimsSetVerifier(jwtClaimsSetVerifier());
        return jwtAccessTokenConverter;
    }

    @Bean
    public CustomJwtClaimsSetVerifier jwtClaimsSetVerifier(){
        return new CustomJwtClaimsSetVerifier();
    }
    @Bean
    public TokenStore tokenStore() {
        return new RedisTokenStore(redisConnectionFactory);
    }

    @Override
    public void configure(WebSecurity webSecurity) {
        webSecurity.ignoring().antMatchers("/swagger-ui/**", "/v3/api-docs/**");
    }
}

