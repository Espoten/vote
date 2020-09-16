package com.shixun.demo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.sql.DataSource;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private DataSource dataSource;
    //进行自定义用户认证
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        //密码：设置编码器
        BCryptPasswordEncoder encoder=new BCryptPasswordEncoder();
        //身份认证
        String userSQL="select username,password,valid from t_user where username = ?";
        String authoritySQL="selece u.username,a.authority from t_user u,t_authority a,"
                +"t_user_authority ua .user_id = u.id"
                +"and ua.authority_id=a.id and u.username =?";
        auth.jdbcAuthentication().passwordEncoder(encoder)
                .dataSource(dataSource)
                .usersByUsernameQuery(userSQL)
                .authoritiesByUsernameQuery(authoritySQL);
    }
}
