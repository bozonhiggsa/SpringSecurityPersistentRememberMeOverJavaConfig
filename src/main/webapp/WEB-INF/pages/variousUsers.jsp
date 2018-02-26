<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <title>Page for various users</title>
</head>
<body>
<h4>Hello <security:authentication property="principal.username" />!</h4>

<security:authorize access="hasRole('USER')">
    This text is only visible to a user
    <br/>
</security:authorize>
<security:authorize access="hasRole('ADMIN')">
    This text is only visible to an admin
    <br/>
</security:authorize>
    <br/>

<c:url value="${pageContext.servletContext.contextPath}/logout" var="loginUrl"/>
<form action="${loginUrl}" method="post">
    <table>
        <input type="hidden"
               name="${_csrf.parameterName}"
               value="${_csrf.token}"/>
        <tr>
            <td><input type="submit" value="Log Out" /></td>
        </tr>
    </table>
</form>

</body>
</html>
