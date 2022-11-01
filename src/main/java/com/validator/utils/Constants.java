package com.validator.utils;

public class Constants {

    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_API_KEY = "X-API-Key";
    public static final String HEADER_AUTHORIZATION_INTER_COMMUNICATION = "Authorization-inter-service-communication";
    public static final String HEADER_AUTHORIZATION_TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_AUTHORIZATION_BASIC_AUTH_PREFIX = "Basic ";


    public static final String USERNAME_KEY = "user_name";
    public static final String CLIENT_ID_KEY = "client_id";
    public static final String UUID_ID_KEY = "user";
    public static final String AUTHORITIES_KEY = "authorities";

    public enum ErrorCode {
        EXPIRED_TOKEN("0001","Token has been expired"),
        INVALID_TOKEN("0002","Invalid Token"),
        GENERAL_EXCEPTION("0003","General Exception");
        String code;
        String value;

        ErrorCode(String code, String value){
            this.code=code;
            this.value=value;
        }

        public String getCode() {
            return code;
        }

        public String getValue() {
            return value;
        }
    }

    public interface ResponseMessage{
        String INVALID_CREDENTIALS = "Username or Password incorrect";
        String INVALID_TOKEN = "Token doesn't contain required details";
        String EXPIRED_TOKEN = "Token has been expired";
    }
}
