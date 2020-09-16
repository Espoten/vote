package com.shixun.demo.client;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

//用户登录模块
@Controller
public class LoginController {
    //跳转到登录页面，并且封装原始页面地址
    @GetMapping(value = "/login" )
    public String login(HttpServletRequest request, Map map){
        String referer =request.getHeader("Referer");
        String url = request.getParameter("url");
        //如果参数url中已经封装了原始页面路径，直接返回该路径
        if (url!=null && !url.equals("")){
            map.put("url",url);
            //如果请求头本身包含登录，将重定向url为空，让后台通过用户角色进行选择跳转
        }else if (referer!=null && referer.contains("/login")){
            map.put("url",url);
            //否则的话，就记住请求头中的原始访问路径
        }else {
            map.put("url",referer);
        }
        return "comm/login";
    }
    @GetMapping(value = "/errorPage/{page}/{code}")
    public String AccessExceptionHandler(@PathVariable("page") String page, @PathVariable("code") String code){
        return page+"/"+code;
    }
}
