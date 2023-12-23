package io.security.corespringsecurity.security.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component("ajaxAuthFailureHandler")
public class AjaxAuthenticationFailureHandler implements AuthenticationFailureHandler {

//    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        String errorMessage = "Invalid username or password";

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        if (exception instanceof DisabledException) {
            errorMessage = "Locked";
        } else if (exception instanceof CredentialsExpiredException) {
            errorMessage = "Expired password";
        }

//        objectMapper.writeValue(response.getWriter(), errorMessage);

        response.getWriter().print(errorMessage);
    }
}
