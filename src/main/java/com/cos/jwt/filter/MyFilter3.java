package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) servletRequest;
        HttpServletResponse res = (HttpServletResponse) servletResponse;

        // 임시 토큰: cos 라고 가정하자.
        if(req.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = req.getHeader("Auhorization");
            System.out.println(headerAuth);
            System.out.println("필터3");

                filterChain.doFilter(req,res);
                // 동작하도록 임의로 내가 변경한 것
//            if(headerAuth.equals("cos")){
//              filterChain.doFilter(req,res);
//            } else{
//                PrintWriter out = res.getWriter();
//                out.println("인증안됨");
//            }
        }

    }
}
