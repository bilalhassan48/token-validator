package com.validator.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@Getter
public class ApplicationProperty {

    @Value("${signing.key}")
    private String signingKey;

    @Value("${enable.cache.verification:false}")
    private Boolean cacheVerificationEnabled;

    @Value("#{'${public.url.path:null}'.split(',')}")
    private String[] publicUrlPath;
}
