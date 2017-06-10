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
	 * 1.doGetAuthenticationInfo ,��ȡ��֤��Ϣ��������ݿ���û�����ݣ�����null,����õ���ȷ���û��������룬����ָ�����͵Ķ���
	 * 2.AuthenticationInfo, ����ʹ��SimpleAuthenticationInfoʵ���࣬��װ��ȷ���û����Լ����룬������
	 * 3.�÷�����Ψһ����AuthenticationToken ���������ڵ���Subject.logon(Token) ��������
	 * �÷�����������֤��
	 */
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationtoken)
			throws AuthenticationException {
		//1.ת��token 
		UsernamePasswordToken token =(UsernamePasswordToken) authenticationtoken;
		SimpleAuthenticationInfo simpleInfo =null ;
		//2.�����û�����ѯ���ݿ�
		Connection conn =null ;
			try {
				Class.forName("com.mysql.jdbc.Driver");
			} catch (ClassNotFoundException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			//3.�����ѯ�����ݣ���װ���
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
					ByteSource salt =ByteSource.Util.bytes(ID); //��ֵ   ���û����е�����
					//����
					SimpleHash hash =new SimpleHash("MD5", realPass, salt, 1024);
					//simpleInfo =new SimpleAuthenticationInfo(realName,hash,this.getName());
					//��ֵ����:Ϊ�˽����ͬ�û�������ͬ���û���������ͬ������
					
					simpleInfo =new SimpleAuthenticationInfo(realName, hash, salt, this.getName());
				}else{
					throw new AuthenticationException();
				}
				
				
			} catch (SQLException e) {
				//4.���û�в鵽���׳��쳣
				e.printStackTrace();
			}
		return simpleInfo;
	}
	/**
	 * �÷�����������Ȩ�� 
	 * AuthorizationInfo:��װ���û���Ӧ��Ȩ�� SimpleAuthorizationInfo(ʵ����)
	 * PrincipalCollection:��¼�����--�û���
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
			//4.���û�в鵽���׳��쳣
			e.printStackTrace();
		}
		
		return info;
	}

	
	
	
	
}
