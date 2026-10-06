package jcms.security;

import tools.jackson.databind.ObjectMapper;
import jcms.config.SpringAppContext;
import jcms.service.UserRoleService;
import jcms.service.UserService;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

// 1. IMPORT THE NEW REPLACEMENT CLASS
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.Collections;

public class JWTLoginFilter extends AbstractAuthenticationProcessingFilter {

	private final ObjectMapper objectMapper = new ObjectMapper();

	public JWTLoginFilter(String url, AuthenticationManager authManager) {
		// 2. USE PATHPATTERNREQUESTMATCHER HERE
		// Note: Spring Security 7 requires the path pattern to begin with a leading forward slash "/"
		super(PathPatternRequestMatcher.pathPattern(
			HttpMethod.POST,
			url.startsWith("/") ? url : "/" + url
		));
		setAuthenticationManager(authManager);
	}

	@Override
	public Authentication attemptAuthentication(
		HttpServletRequest request,
		HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

		LoginCredentials login = objectMapper.readValue(request.getInputStream(), LoginCredentials.class);

		return getAuthenticationManager().authenticate(
			new UsernamePasswordAuthenticationToken(
				login.getUsername(),
				login.getPassword(),
				Collections.emptyList()
			)
		);
	}

	@Override
	protected void successfulAuthentication(
		HttpServletRequest request,
		HttpServletResponse response,
		FilterChain chain,
		Authentication authResult) throws IOException, ServletException {

		String loginUsername = authResult.getName();
		ApplicationContext applicationContext = SpringAppContext.getApplicationContext();
		UserService userService = (UserService) applicationContext.getBean("userService");
		UserRoleService userRoleService = (UserRoleService) applicationContext.getBean("userRoleService");

		try {
			final String role = userRoleService.findByForeignKeyUserUsername(loginUsername).getRole().getRoleName();
			JWTPayload jwtPayload = new JWTPayload(loginUsername, role);
			TokenService.addJWTAuthentication(response, jwtPayload);
		} catch (Exception e) {
			logger.error("Failed to assemble JWT claims payload context profiles", e);
		}
	}
}
