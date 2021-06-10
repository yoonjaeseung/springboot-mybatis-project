package com.spring.springbootmybatisproject.security.controller;

import com.spring.springbootmybatisproject.security.model.entity.User;
import com.spring.springbootmybatisproject.security.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@Slf4j
@Controller
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping(value = {"/", "/slogin"})
    public ModelAndView getLoginPage() {
        ModelAndView mv = new ModelAndView();


        mv.setViewName("user/login");
        return mv;
    }

    @PostMapping("/sloginProc")
    public void findLoginInfo(User user, HttpServletResponse response) {
//        ModelAndView mv = new ModelAndView();
//        User userInfo = userService.findUser(user);
//        mv.addObject("user", userInfo);
//        mv.setViewName("user/home");

        userService.findUser(user);
        System.out.println("login complete");

    }

    @GetMapping("/registration")
    public ModelAndView getRegistrationPage() {
        ModelAndView mv = new ModelAndView();
        User user = new User();
        mv.addObject("user", user);
        mv.setViewName("user/registration");
        return mv;
    }

    @PostMapping("/registration")
    public ModelAndView createNewUser(@Valid User user, BindingResult bindingResult) {
        ModelAndView mv = new ModelAndView();
        User userExists = userService.findUserByLoginId(user.getLoginId());
        if (userExists != null) {
            bindingResult.rejectValue("loginId", "error.loginId", "There is already a user registered with the loginId provided");
        }
        if (bindingResult.hasErrors()) {
            mv.setViewName("user/registration");
        } else {
            userService.saveUser(user);

            mv.addObject("successMessage", "User has been registered successfully");
            mv.addObject("user", new User());
            mv.setViewName("user/registration");
        }
        return mv;
    }

    @GetMapping("/home")
    public ModelAndView home() {
        ModelAndView mv = new ModelAndView();
//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        UserPrincipal2 userPrincipal2 = (UserPrincipal2) auth.getPrincipal();


//        Object userPrincipal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
//                    UserDetails userDetails = (UserDetails) userPrincipal;

//        String username = ((UserDetails) userPrincipal2).getUsername();
//        String password = ((UserDetails) userPrincipal2).getPassword();
//
//        log.info("name: {}, pass: {}", username, password);

//        if (userPrincipal instanceof UserPrincipal2) {
//            String userName = ((UserPrincipal2) userPrincipal).getUsername();
//            System.out.println("true: " + userName);
//        } else {
//            String userName = userPrincipal.toString();
//            System.out.println("false: " + userName);
//        }


//        System.out.println(userPrincipal2.toString());
//        mv.addObject("userName", "Welcome " + userPrincipal2.getName() + " (" + userPrincipal2.getId() + ")");
        mv.addObject("adminMessage", "Content Available Only for Users with Admin Role");
        mv.setViewName("user/home");
        return mv;
    }

    @GetMapping("/exception")
    public ModelAndView getUserPermissionExceptionPage() {
        ModelAndView mv = new ModelAndView();
        mv.setViewName("user/access-denied");
        return mv;
    }

}
