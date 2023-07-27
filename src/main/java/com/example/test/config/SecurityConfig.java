package com.example.test.config;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationFilter;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Configuration
@EnableWebSecurity(debug = true) 
// WebSecurityConfiguration 등 웹 보안 활성화를 위한 여러 클래스들을 import 해준다.
// WebSecurityConfigurerAdapter -> 스프링 어플리케이션이 시작 시 동작, 웹 보안 기본 설정 초기화 수행
@RequiredArgsConstructor
@Log4j2
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	
	private final UserDetailsService userDetailService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// HttpSecurity는 사용자의 세부적인 보안 기능을 설정할 수 있다.
		//             다앙한 인증 및 인가와 관련된 API를 제공한다.
		
		// 각 Resource별 권한
		http.authorizeRequests()
			.antMatchers("/sessionOver").permitAll()
			.anyRequest().authenticated();
		
		// 로그인
		http.formLogin()
//			.loginPage("/loginPage")
//			.defaultSuccessUrl("/") // successHandler로 대체.
			.successHandler((request, response, authentication) -> {
				log.info("#### Authentication success...");
				response.sendRedirect("/");
			})
//			.failureUrl("/login") // failureHandler로 대체
			.failureHandler((request, response, exception) -> {
				log.info("#### Authentication fail...");
				
				exception.printStackTrace();
				
				response.sendRedirect("/login");
			})
			.usernameParameter("userId") // form 아이디 파라미터 키 값
			.passwordParameter("passwd") // form 비밀번호 파라미터 키 값
			.permitAll(); // 로그인 페이지는 모든 권한 접근 가능
		
		// 로그아웃
		http.logout()
			.logoutUrl("/logout")
//			.logoutSuccessUrl("/login") // 로그아웃 처리 URL. logoutSuccessHandler로 대체
			.logoutSuccessHandler((request, response, authentication) -> {
				response.sendRedirect("/login");
			})
			.addLogoutHandler(((request, response, authentication) -> {
//				HttpSession session = request.getSession();
//				if(session != null) session.invalidate();
				// 위 과정을 LogoutFilter가 해줌.
				// 여기서 설정된 핸들러가 먼저 실행 되고 그다음 기본 Logout Handler가 실행된다.
				log.info("#### logout handler..");
			}))
			.deleteCookies("remember-me"); // 로그 아웃 후 삭제할 쿠키 지정
		
		// remember-Me
		http.rememberMe()
			.rememberMeParameter("remember-me") // 기본명은 remember-me.
			.tokenValiditySeconds(3600) // 만료시간. 기본은 14일.
//			.alwaysRemember(true) // 로그인 하면 무조건 Remeber-me 활성화
			.userDetailsService(userDetailService); // 안하면 java.lang.IllegalStateException: UserDetailsService is required 예외 발생.
												    // 내부적인 재인증을 위해서는 UserDetailsService 객체가 필요.
		// session 제어
		http.sessionManagement()
			.sessionFixation()  // 세션 고정 보호
			.changeSessionId()  // 사용자 인증 성공 시, 세션 자체는 그대로 두고 세션 아이디만 변경 서블릿 3.1 이상에서 기본값
//			.migrateSession(); // 새로운 세션 생성 + 세션 아이디 새로 발급. 서블릿 3.1 미만에서 기본 값
//			.newSession();     // 새로운 세션 생성 + 세션 아이디 새로 발급. 기존 세션 속성 값 모두 사라짐.
//			.none();           // 사용안함
			
			.invalidSessionUrl("/login") // 세션이 유효하지 않을 때 이동할 페이지
										 // expiredUrl도 설정되어있는 경우, invalidSessionUrl이 우선순위를 갖는다.
			.maximumSessions(1)
//			.expiredSessionStrategy(event -> {
//				log.info("#### expired..");
//				
//				event.getResponse().sendRedirect("/sessionOver");
//			}) // 다른 사용자가 로그인하여 세션이 만료된 경우.
			.maxSessionsPreventsLogin(true); // 현재 사용자 인증 실패 방식 설정
											 // false : 이전 사용자 세션 만료
											 // true  : 현재 사용자 인증 실패
	}// configure
	
	/**
	 * maxSessionsPreventsLogin(true)로 설정하려면 아래와 같이 설정.
	 * @return
	 */
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}// sessinRegistry
	
	@Bean
	public static ServletListenerRegistrationBean httpSessionEventPublisher() {
		return new ServletListenerRegistrationBean(new HttpSessionEventPublisher());
	}// httpSessionEventPublisher
	
}// SecurityConfig




















