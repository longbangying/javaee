<%@ page language="java" contentType="text/html; charset=utf-8"
    pageEncoding="utf-8"%>
<%@ taglib prefix="shiro" uri="http://shiro.apache.org/tags" %>
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Insert title here</title>
</head>
<body>
	<h3>success Page</h3>
	

		<shiro:hasRole name="admin">	
		<br/>
			<a href="admin.jsp">admin Page</a>
		<br/>
		</shiro:hasRole>
	
	
		<shiro:user>
			<br/>
				<a href="user.jsp">user Page</a>
			<br/>
		</shiro:user>
	
	<a href="logout">注销</a>
</body>
</html>