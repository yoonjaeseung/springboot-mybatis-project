package com.spring.springbootmybatisproject.security.model.domain;

import com.spring.springbootmybatisproject.security.model.entity.User;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

@ToString
@Getter

public class UserPrincipal2 implements UserDetails {

    private User user;

    public UserPrincipal2(User user) {
        this.user = user;
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singletonList(new UserGrant());
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return user.getActive() == 1;
    }

    public String getId() {
        return user.getLoginId();
    }

    public String getName() {
        return user.getUserName();
    }
}
