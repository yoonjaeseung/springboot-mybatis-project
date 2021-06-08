package com.spring.springbootmybatisproject.security.model.domain;

import com.spring.springbootmybatisproject.account.model.NAccountVO;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Arrays;
import java.util.Collection;

@ToString
@Getter

public class UserPrincipal implements UserDetails {

    private NAccountVO nAccountVO;

    public UserPrincipal(NAccountVO nAccountVO) {
        this.nAccountVO = nAccountVO;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Arrays.asList(new UserGrant());
    }

    @Override
    public String getPassword() {
//        return user.getPassword();
        return nAccountVO.getAccountPassword();
    }

    @Override
    public String getUsername() {
//        return user.getUserName();
        return nAccountVO.getAccountUserNm();
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
        return nAccountVO.getActive() == 1;
    }

    public String getId() {
//        return user.getLoginId();
        return nAccountVO.getAccountUserId();
    }

    public String getName() {
//        return user.getUserName();
        return nAccountVO.getAccountUserNm();
    }
}
