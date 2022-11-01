package com.validator.dto;

import com.validator.utils.Constants;
import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@ToString
@Builder
public class ErrorInfo {
    String code;
    String message;
    String trackCode;

    public ErrorInfo(Constants.ErrorCode errorCode) {
        this.code = errorCode.getCode();
        this.message = errorCode.getValue();
    }

    @Override
    public String toString() {
        return "ErrorInfo{" + "code='" + code + '\'' + ", message='" + message + '\'' + ", trackCode='" + trackCode + '}';
    }
}
