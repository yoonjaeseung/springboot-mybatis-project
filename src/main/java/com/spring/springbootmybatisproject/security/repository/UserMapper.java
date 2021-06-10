package com.spring.springbootmybatisproject.security.repository;

import com.spring.springbootmybatisproject.security.model.entity.User;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.springframework.stereotype.Component;

@Component
@Mapper
public interface UserMapper {
    User findUserByLoginId(@Param("loginId") String loginId);
    int setUserInfo(@Param("param") User param);

    void findUser(User user);
}
