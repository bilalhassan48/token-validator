/*
package com.validator.utils;

import com.validator.dto.UserDto;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class CustomerUtils {

    public String getPrincipalUuid() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return ((UserDto) authentication.getPrincipal()).getUuid();
    }

    public boolean isValidUuid(String uuid){
        return uuid!=null && uuid.equalsIgnoreCase(getPrincipalUuid());
    }
}
*/
