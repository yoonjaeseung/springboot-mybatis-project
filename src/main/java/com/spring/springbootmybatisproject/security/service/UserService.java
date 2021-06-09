package com.spring.springbootmybatisproject.security.service;
import com.spring.springbootmybatisproject.security.model.domain.UserPrincipal2;
import com.spring.springbootmybatisproject.security.repository.RoleMapper;
import com.spring.springbootmybatisproject.security.repository.UserMapper;
import com.spring.springbootmybatisproject.security.repository.UserRoleMapper;
import com.spring.springbootmybatisproject.security.model.entity.Role;
import com.spring.springbootmybatisproject.security.model.entity.User;
import com.spring.springbootmybatisproject.security.model.entity.UserRole;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService implements UserDetailsService {

    private final UserMapper userMapper;
    private final RoleMapper roleMapper;
    private final UserRoleMapper userRoleMapper;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserMapper userMapper, RoleMapper roleMapper, UserRoleMapper userRoleMapper, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userMapper = userMapper;
        this.roleMapper = roleMapper;
        this.userRoleMapper = userRoleMapper;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public User findUserByLoginId(String loginId){
        return userMapper.findUserByLoginId(loginId);
    }

    public void saveUser(User user){
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setActive(1);
        userMapper.setUserInfo(user);

        Role role = roleMapper.getRoleInfo("ADMIN");

        UserRole userRole = new UserRole();
        userRole.setRoleId(role.getId());
        userRole.setUserId(user.getId());
        userRoleMapper.setUserRoleInfo(userRole);

    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.findUserByLoginId(username);
        return new UserPrincipal2(user);
    }

    public User findUser(User user) {
        return userMapper.findUser(user);
    }
}
