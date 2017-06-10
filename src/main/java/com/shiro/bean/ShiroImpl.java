package com.shiro.bean;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.crypto.hash.SimpleHash;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;
//implements Realm
public class ShiroImpl extends AuthorizingRealm {
	/**
	 * 
	 * 1.doGetAuthenticationInfo ,获取认证消息，如果数据库中没有数据，返回null,如果得到正确的用户名何密码，返回指定类型的对象
	 * 2.AuthenticationInfo, 可以使用SimpleAuthenticationInfo实现类，封装正确的用户名以及密码，并返回
	 * 3.该方法的唯一参数AuthenticationToken 就是我们在调用Subject.logon(Token) 传进来的
	 * 该方法是用来认证的
	 */
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationtoken)
			throws AuthenticationException {
		//1.转化token 
		UsernamePasswordToken token =(UsernamePasswordToken) authenticationtoken;
		SimpleAuthenticationInfo simpleInfo =null ;
		//2.根据用户名查询数据库
		Connection conn =null ;
			try {
				Class.forName("com.mysql.jdbc.Driver");
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//3.如果查询到数据，封装结果
			try {
				conn =DriverManager.getConnection("jdbc:mysql://localhost:3306/web","root","soar");
				PreparedStatement preparedStatement =conn.prepareStatement("select * from soar_user where user_name =?");
				preparedStatement.setString(1, token.getUsername());
				ResultSet set =preparedStatement.executeQuery();
				String realName ="";
				String realPass ="";
				if(set.next()){
					realName=set.getString(2);
					realPass =set.getString(3);
					String ID= set.getString(1);
					ByteSource salt =ByteSource.Util.bytes(ID); //盐值   用用户表中的主键
					//加密
					SimpleHash hash =new SimpleHash("MD5", realPass, salt, 1024);
					//simpleInfo =new SimpleAuthenticationInfo(realName,hash,this.getName());
					//盐值加密:为了解决不同用户设置相同的用户设置了相同的密码
					
					simpleInfo =new SimpleAuthenticationInfo(realName, hash, salt, this.getName());
				}else{
					throw new AuthenticationException();
				}
				
				
			} catch (SQLException e) {
				//4.如果没有查到，抛出异常
				e.printStackTrace();
			}
		return simpleInfo;
	}
	/**
	 * 该方法是用来授权的 
	 * AuthorizationInfo:封装了用户对应的权限 SimpleAuthorizationInfo(实现类)
	 * PrincipalCollection:登录的身份--用户名
	 * 
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalcollection) {
		// TODO Auto-generated method stub
		SimpleAuthorizationInfo info =null;
		Connection conn =null ;
		try {
			Class.forName("com.mysql.jdbc.Driver");
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		String sql ="select role_name from soar_role where role_id in(select role_id from soar_role_user where user_id in (select user_id from soar_user where user_name =?) )";
		try {
			conn =DriverManager.getConnection("jdbc:mysql://localhost:3306/web","root","soar");
			PreparedStatement preparedStatement =conn.prepareStatement(sql);
			preparedStatement.setString(1, principalcollection.toString());
			ResultSet set =preparedStatement.executeQuery();
			Set<String> roles =new HashSet<String>();
			while(set.next()){
				roles.add(set.getString(1));
			}
			info =new SimpleAuthorizationInfo(roles);
		} catch (SQLException e) {
			//4.如果没有查到，抛出异常
			e.printStackTrace();
		}
		
		return info;
	}

	
	
	
	
}
