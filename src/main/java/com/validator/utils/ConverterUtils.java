package com.validator.utils;

import com.validator.dto.ErrorInfo;
import lombok.extern.slf4j.Slf4j;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;

@Slf4j
public class ConverterUtils {

    public static String convertToJson(ErrorInfo object){
        ObjectMapper mapper = new ObjectMapper();
        String jsonStr = object!=null ? object.toString() : "";
        try {
            // Java objects to JSON string
            jsonStr = mapper.writeValueAsString(object);

        } catch (IOException e) {
            log.error("Exception occurred while converting ErrorInfo to JSON", e);
        }
        return jsonStr;
    }
}
