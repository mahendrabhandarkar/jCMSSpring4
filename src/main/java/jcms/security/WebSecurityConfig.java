package jcms.security;

import jcms.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig {

	@Autowired
	private MyUserDetailsService myUserDetailsService;

	/**
	 * 1. Define the AuthenticationManager explicitly as a Bean.
	 * This replaces the old configure(AuthenticationManagerBuilder auth) method overrides.
	 */
	@Bean
	public AuthenticationManager authenticationManager() {
		// Build the hard-coded admin account
		UserDetails admin = User.withUsername("admin")
			.password(UserServiceImpl.PASSWORD_ENCODER.encode("password")) // Explicit encoding is now mandatory
			.roles("owner")
			.build();

		InMemoryUserDetailsManager inMemoryAuth = new InMemoryUserDetailsManager(admin);

		// Wire up both the In-Memory engine and your database-backed engine
		return new ProviderManager(
			List.of(
				getDaoAuthenticationProvider(inMemoryAuth),
				getDaoAuthenticationProvider(myUserDetailsService)
			)
		);
	}

	/**
	 * 2. Replace configure(HttpSecurity http) with a SecurityFilterChain Bean.
	 * Uses modern Lambda DSL declarations.
	 */
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http, AuthenticationManager authManager) throws Exception {
		http
			// Modern functional lambda style to disable CSRF
			.csrf(csrf -> csrf.disable())

			// Replaced .authorizeRequests() with the modern .authorizeHttpRequests()
			.authorizeHttpRequests(auth -> auth
				.requestMatchers("/login").permitAll()
				.requestMatchers("/api/private/**").authenticated()
				.requestMatchers("/admin/**").authenticated()
				.anyRequest().permitAll() // Good practice fallback
			)

			// Because you are using JWT cookies, explicitly state that sessions should be Stateless
			.sessionManagement(session -> session
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			)

			.formLogin(form -> form
				.loginPage("/login")
				.permitAll()
			)

			.logout(logout -> logout
				.logoutSuccessUrl("/")
				.permitAll()
			)

			// Register your modern custom JWT filters using the active AuthenticationManager bean context
			.addFilterBefore(new JWTLoginFilter("/login", authManager), UsernamePasswordAuthenticationFilter.class)
			.addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	/**
	 * 3. Replace configure(WebSecurity web) with WebSecurityCustomizer.
	 * This completely ignores internal web resources from the security filters entirely.
	 */
	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring().requestMatchers("/resources/**", "/static/**", "/css/**", "/js/**");
	}

	private DaoAuthenticationProvider getDaoAuthenticationProvider(org.springframework.security.core.userdetails.UserDetailsService detailsService) {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider(detailsService); // Constructor Injection
		provider.setPasswordEncoder(UserServiceImpl.PASSWORD_ENCODER);
		return provider;
	}
}
