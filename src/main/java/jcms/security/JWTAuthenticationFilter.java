package jcms.security;

import io.jsonwebtoken.SignatureException; // Updated root package import path
import jcms.security.TokenService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.GenericFilterBean;
import org.springframework.security.core.Authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JWTAuthenticationFilter extends GenericFilterBean {

	@Override
	public void doFilter(
		ServletRequest request,
		ServletResponse response,
		FilterChain filterChain) throws IOException, ServletException {

		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		try {
			Authentication authentication = TokenService.getJWTAuthentication(httpRequest);

			if (authentication != null) {
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}

			filterChain.doFilter(httpRequest, httpResponse);

		} catch (SignatureException e) {
			// Catches tampered tokens using the 0.12.x signature validation routine
			TokenService.deleteJwtCookie(httpRequest, httpResponse);
			httpResponse.sendRedirect("/login");
		}
	}
}
