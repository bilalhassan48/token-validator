package com.validator.exception;

import com.validator.dto.ErrorInfo;
import com.validator.utils.Constants;


public class TokenValidationException extends RuntimeException {
	private ErrorInfo errorCode;

	public TokenValidationException(ErrorInfo errorCode) {
		super(errorCode.getMessage());
		this.errorCode = errorCode;
	}

	public TokenValidationException(Constants.ErrorCode errorCode) {
		super(errorCode.getValue());
		this.errorCode = new ErrorInfo(errorCode.getCode(),errorCode.getValue(),null);
	}

	public TokenValidationException(ErrorInfo errorCode, Throwable cause) {
		super(errorCode.getMessage(), cause);
		this.errorCode = errorCode;
	}

	public ErrorInfo getErrorCode() {
		return errorCode;
	}
}
