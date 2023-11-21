package com.pokemonreview.api.exceptions.advice;

import com.pokemonreview.api.exceptions.ErrorObject;
import com.pokemonreview.api.exceptions.MyResourceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {
    @ExceptionHandler(MyResourceException.class)
    public ResponseEntity<ErrorObject> handleResourceNotFoundException(MyResourceException ex) {
        ErrorObject errorObject = new ErrorObject();
        errorObject.setStatusCode(ex.getStatusCode());
        errorObject.setMessage(ex.getMessage());

        return new ResponseEntity<ErrorObject>(errorObject, HttpStatus.resolve(ex.getStatusCode()));
    }

    @ExceptionHandler(Exception.class)
    protected ResponseEntity<Object> handleException(Exception e) {
        Map<String, Object> result = new HashMap<String, Object>();
        ResponseEntity<Object> ret = null;

        result.put("message", e.getMessage());
        result.put("httpStatus", HttpStatus.INTERNAL_SERVER_ERROR.value());
        ret = new ResponseEntity<>(result, HttpStatus.INTERNAL_SERVER_ERROR);
        e.printStackTrace();

        log.error(e.getMessage(), e);
        return ret;
    }

		//403
    @ExceptionHandler(value = AccessDeniedException.class)
    public void accessDeniedExceptionHandler(Exception e) {
        throw new AccessDeniedException(e.getMessage());
    }
		
		//401
		@ExceptionHandler(value = BadCredentialsException.class)
    public void badCredentialExceptionHandler(BadCredentialsException e){
        throw new BadCredentialsException(e.getMessage());
    }
   
}