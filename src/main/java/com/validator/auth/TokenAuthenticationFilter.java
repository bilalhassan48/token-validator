package com.validator.auth;

import com.validator.config.ApplicationProperty;
import com.validator.config.CustomJwtTokenEnhancer;
import com.validator.dto.ErrorInfo;
import com.validator.dto.UserDto;
import com.validator.exception.TokenValidationException;
import com.validator.utils.Constants;
import com.validator.utils.ConverterUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;

@Slf4j
public class TokenAuthenticationFilter extends OncePerRequestFilter {

    private CustomJwtTokenEnhancer customJwtTokenEnhancer;

    private ApplicationProperty applicationProperty;

    private AntPathMatcher pathMatcher;

    public TokenAuthenticationFilter(CustomJwtTokenEnhancer customJwtTokenEnhancer, ApplicationProperty applicationProperty) {
        this.customJwtTokenEnhancer = customJwtTokenEnhancer;
        this.applicationProperty = applicationProperty;
        this.pathMatcher = new AntPathMatcher();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            final String apiKey = getAppKeyFromRequest(request);
            if(StringUtils.hasText(apiKey)){
                String[] usernamePassword = getUsernamePassword(request);
//                if (!validateClient(usernamePassword[0], usernamePassword[1], apiKey)) {
                if (!validateClient()) {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.getWriter().write(Constants.ResponseMessage.INVALID_CREDENTIALS);
                }else{
                    validateToken(request,Map.of(Constants.USERNAME_KEY,usernamePassword[0]) , usernamePassword[0]);
                    filterChain.doFilter(request, response);
                }
            }else{
                String jwt = getJwtFromRequest(request);
                Map<String, Object> userDetails = customJwtTokenEnhancer.decode(jwt);

                String userId = "";
                if(userDetails.containsKey(Constants.USERNAME_KEY)){
                    userId = (String)userDetails.get(Constants.USERNAME_KEY);
                }else if(userDetails.containsKey(Constants.CLIENT_ID_KEY)){
                    userId = (String)userDetails.get(Constants.CLIENT_ID_KEY);
                }else{
                    throw new InvalidTokenException(Constants.ResponseMessage.INVALID_TOKEN);
                }

                if(applicationProperty.getCacheVerificationEnabled() && !customJwtTokenEnhancer.validateToken(jwt))
                    throw new InvalidTokenException(Constants.ResponseMessage.EXPIRED_TOKEN);

                validateToken(request, userDetails, userId);

            }

        } catch (InvalidTokenException ex){
            if (ex.getCause() instanceof TokenValidationException exception){
                writeResponse(response, exception.getErrorCode());
            }else{
                writeResponse(response, new ErrorInfo(Constants.ErrorCode.INVALID_TOKEN));
            }
            return;
        } catch(Exception ex) {
            log.info("Could not set token authentication in security context ", ex);
            writeResponse(response, new ErrorInfo(Constants.ErrorCode.EXPIRED_TOKEN.getCode(), ex.getMessage(),null));
            return;
        }
        filterChain.doFilter(request, response);
    }

    private void writeResponse(HttpServletResponse response, ErrorInfo errorInfo) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write(ConverterUtils.convertToJson(errorInfo));
    }


    private boolean validateClient(/*String clientId, String password, String apiKey*/){
        /*Optional<Client> clientOptional = clientRepository.findByClientIdAndApiKeyAndActive(clientId, apiKey, true);
        return clientOptional.isPresent() && clientOptional.get().getSecretKey().equals(password);*/
        return false;
    }

    private void validateToken(HttpServletRequest request, Map<String, Object> userDetails, String username) {
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(getUserDto(userDetails), null, getAuthorities(userDetails));
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        log.info(username);
    }

    private String getJwtFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(Constants.HEADER_AUTHORIZATION);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(Constants.HEADER_AUTHORIZATION_TOKEN_PREFIX)) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    private String[] getUsernamePassword(HttpServletRequest request){
        String basicAuth = request.getHeader(Constants.HEADER_AUTHORIZATION);
        String encodedString = null;
        if (StringUtils.hasText(basicAuth) && basicAuth.startsWith(Constants.HEADER_AUTHORIZATION_BASIC_AUTH_PREFIX)) {
           encodedString = basicAuth.substring(6, basicAuth.length());
        }
        return decode(encodedString);
    }

    private static String[] decode(final String encoded) {
        if(StringUtils.hasText(encoded)){
            final byte[] decodedBytes
                    = Base64.decodeBase64(encoded.getBytes());
            final String pair = new String(decodedBytes);
            return pair.split(":", 2);
        }
        return new String[0];
    }

    private String getAppKeyFromRequest(HttpServletRequest request){
        String apiKey = request.getHeader(Constants.HEADER_API_KEY);
        return StringUtils.hasText(apiKey) ? apiKey : null;
    }



    private Set<GrantedAuthority> getAuthorities(Map<String, Object> data){
        Set<GrantedAuthority> authorities = new HashSet<>();
        List<String> authoritiesList = (List<String>) data.get(Constants.AUTHORITIES_KEY);
        if(null != authoritiesList) {
            authoritiesList.forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority)));
        }
        return authorities;
    }

    private UserDto getUserDto(Map<String, Object> map){
        return UserDto
                .builder()
                .uuid((String) map.get(Constants.UUID_ID_KEY))
                .clientId((String) map.get(Constants.CLIENT_ID_KEY))
                .username((String) map.get(Constants.USERNAME_KEY))
                .authorities((ArrayList<String>) map.get(Constants.AUTHORITIES_KEY))
                .build();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String[] skipUrls = applicationProperty.getPublicUrlPath();
        return List.of(skipUrls).stream().anyMatch(path -> pathMatcher.match(path, request.getServletPath()));
    }
}
