<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>
<html>
<head>
    <title>My Login page</title>
    <script type="text/javascript">
        function validate() {
            if (document.f.username.value == "" && document.f.password.value == "") {
                alert("Username and password are required");
                document.f.username.focus();
                return false;
            }
            if (document.f.username.value == "") {
                alert("Username is required");
                document.f.username.focus();
                return false;
            }
            if (document.f.password.value == "") {
                alert("Password is required");
                document.f.password.focus();
                return false;
            }
        }
    </script>
</head>
<body>
<c:url value="${pageContext.servletContext.contextPath}/login" var="loginUrl"/>
<form name="f" action="${loginUrl}" method="post" onsubmit="return validate();">
    <c:if test="${param.error != null}">
        <p>
            Invalid username and password.
        </p>
    </c:if>
    <c:if test="${param.logout != null}">
        <p>
            You have been logged out.
        </p>
    </c:if>
    <table>
        <tr>
            <td><label for="username">Username:</label></td>
            <td><input type="text" id="username" name="username"></td>
        </tr>
        <tr>
            <td><label for="password">Password:</label></td>
            <td><input type="password" id="password" name="password" /></td>
        </tr>
        <tr>
            <td><label for="remember-me">Remember Me</label></td>
            <td><input type="checkbox" id="remember-me" name="remember-me" /></td>
        </tr>
        <input type="hidden"
               name="${_csrf.parameterName}"
               value="${_csrf.token}"/>
        <tr>
            <td><input type="submit" value="Sign In" /></td>
        </tr>
    </table>
</form>

</body>
</html>