//package com.spring.springbootmybatisproject.config;
//
//import lombok.AllArgsConstructor;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.builders.WebSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
//@Configuration
//@EnableWebSecurity
//@AllArgsConstructor
//public class SecurityConfig extends WebSecurityConfigurerAdapter {
//
//    // 패스워드 암호화
//    @Bean
//    public PasswordEncoder getPasswordEncoder() {
//        return new BCryptPasswordEncoder();
//    }
//
////    @Bean
////    public CustomLoginSuccessHandler loginSuccessHandler() {
////        return new CustomLoginSuccessHandler();
////    }
//
////    @Override
////    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
////        auth.userDetailsService(nccountService);
////    }
//
//    @Override
//    public void configure(WebSecurity web) throws Exception {
//        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**", "/d3/**", "/font/**"); // 인증 무시
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        http
////                .cors().disable()      // cors 비활성화
////                .csrf().disable()      // csrf 비활성화
////                .formLogin().disable() //기본 로그인 페이지 없애기
////                .headers().frameOptions().disable();
//
//
//        /* 실제 사용 */
//        http
//            .csrf()
//                .disable() // csrf 비활성화
//            .authorizeRequests() // 페이지 인증 해제
//                .antMatchers("/"
//                        , "/resources/**"
//                        , "/nAccount/**"
//                        , "/board/**"
//                        ).permitAll()
//                .antMatchers("/survey/list"
//                        ,"/survey/main"
//                        ).hasRole("USER")
//                .anyRequest() // 위 지정한 URL 이외 모든 URL
//                .authenticated() // 인증된 사용자만 접근 가능
//            .and()
//            .formLogin()
//                .loginPage("/nAccount/login") // 로그인이 수행 될 페이지
////                .loginProcessingUrl("/nAccount/loginProc") // <form action> 일 경우 사용
//                .defaultSuccessUrl("/") // 로그인 성공 시 이동 페이지
////                .failureUrl() // 로그인 실패 시 보여주는 화면
//                .usernameParameter("accountUserId")
//                .passwordParameter("accountPassword");
//
//    }
//
//
//
//}
