package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.Repository.UserRepository;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    // 인증이나 권한이 필요한 주소요청이 있을 떄 해당 필터를 타게 된다.
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {

        System.out.println("인증이나 권한이 필요한 주소 요청 됨.");

        // jwt header에 Authorization에 토큰이 주입되면
        // jwtHeader에 토큰 값이 들어온다.
        String jwtHeader = request.getHeader("Authorization");
        System.out.println("jwtHeader: " + jwtHeader);

        if(jwtHeader == null || !jwtHeader.startsWith("Bearer")){
            chain.doFilter(request,response);
            return;
        }

        // JWT 토큰을 검증을 해서 정상적인 사용자인지 확인
        // Bearer을 지우고 토큰만 남기기 위해서 Bearer 뒤에 한칸 띄기 필수
        String jwtToken =request.getHeader("Authorization").replace("Bearer ","");

        // 동작 방법
        // cos라는 시크릿키를 가지고 HMAC512 알고리즘을 이용하여 jwtToken을 서명한 후 payload에 있는
        // username이라는 값을 가져올 것이다. 라는 의미이다.
        String username = JWT.require(Algorithm.HMAC512("cos")).
                build().verify(jwtToken).getClaim("username").asString();

        // 서명이 되었다는 뜻
        if(username != null){
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // JwtAuthentication에서 authenticationManager.authenticate(authenticationToken);
            // 를 이용해서 정상적인 로그인 인증을 해주었지만
            // 밑에 코드는 강제로 인증을 해주는 것이다.
            // new UsernamePasswordAuthenticationToken(principalDetails,"비밀번호","권한을 알려주는 것") 하지만 강제로 할 것이기 떄문에
            // 비밀번호를 null로 해주어도 된다.
            // 강제로 만들어도 되는 이유는 위에서 토큰을 통해 인증이 되었다는 것을 알기에 가능한 것이다.
            // 떄문에!! 인증이 필요한 페이지에 접근할 때마다 토큰을 같이 서버로 보내주어 강제로 인증을 통해 인증된 서버로 넘기는 것이다.
            // Authentication은 세션 영역이다. => 권한마다 페이지가 달라지려면 세션이 필요하다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null,principalDetails.getAuthorities());

            // 시큐리티를 저장할 세션 공간을 찾는 코드 .getContext()
            // 강제로 시큐리티의 세션에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request,response);
        }
    }
}
