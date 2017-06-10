package com.shiro.action;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.apache.shiro.cache.ehcache.EhCacheManager;
@Controller
public class LogonAction {
	
	
	@RequestMapping("/logon")
	public String logon(@RequestParam(name="username")String userName,
			@RequestParam(name="password") String pass){
		Subject currentUser =SecurityUtils.getSubject();
		if(!currentUser.isAuthenticated()){
			UsernamePasswordToken token =new UsernamePasswordToken();
			token.setUsername(userName);
			token.setPassword(pass.toCharArray());
			try{
				currentUser.login(token);
				
			}catch(AuthenticationException e){
				System.out.println("登录失败...");
				return "logonfailur";
			}
			
		}
		return "success";
		
	}
	
	/**
	 * shiro 笔记
	 * 
	 * shiro  中的密码比对 
	 * 
	 * 
	 * 
	 * 
	 * 
	 */
	
	
}
