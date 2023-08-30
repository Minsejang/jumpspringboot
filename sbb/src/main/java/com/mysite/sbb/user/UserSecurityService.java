package com.mysite.sbb.user;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Service
public class UserSecurityService implements UserDetailsService {
	
	private final UserRepository userRepository;
	
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// 사용자 이름(username)으로 데이터베이스에서 사용자 정보를 찾습니다.
		Optional<SiteUser> _siteUser = this.userRepository.findByusername(username);
		
		// 사용자 정보가 존재하지 않으면 예외를 던집니다.
		if (_siteUser.isEmpty()) {
			throw new UsernameNotFoundException("사용자를 찾을 수 없습니다.");
		}
		
		// 데이터베이스에서 찾은 사용자 정보를 가져옵니다.
		SiteUser siteUser = _siteUser.get();
		
		// 사용자의 권한(authorities)를 담을 리스트를 생성합니다.
		List<GrantedAuthority> authorities = new ArrayList<>();
		
		// 사용자 이름이 "admin"인 경우 ADMIN 권한을 부여합니다.
		if ("admin".equals(username)) {
			authorities.add(new SimpleGrantedAuthority(UserRole.ADMIN.getValue()));
		} else {
            authorities.add(new SimpleGrantedAuthority(UserRole.USER.getValue()));
        }
		
		// Spring Security에서 제공하는 User 객체를 생성하여 반환합니다.
		// User 객체는 UserDetails 인터페이스를 구현한 클래스로, 사용자 정보와 권한 정보를 담고 있습니다.
		return new User(siteUser.getUsername(), siteUser.getPassword(), authorities);
	}
}