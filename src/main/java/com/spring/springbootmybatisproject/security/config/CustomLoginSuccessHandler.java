package com.spring.springbootmybatisproject.security.config;//package com.spring.springbootmybatisproject.securitydemo;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

/**
 * Created by berno579@gmail.com on 2021/06/06
 * Github : http://github.com/bee0113
 */
// 참고 URL: https://galid1.tistory.com/698?category=791456

//로그인 성공시 처리할 로직
@Slf4j
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession();

        session.setAttribute("greeting", authentication.getName() + "님 반가워요."); // Authentication의 getName() 메소드를 통해 로그인한 사용자 이름을 알 수 있음

        log.info("authentication Name: {}",authentication.getName());
        response.sendRedirect("/home"); // 성공 시 리다렉트할 URL
    }
}
