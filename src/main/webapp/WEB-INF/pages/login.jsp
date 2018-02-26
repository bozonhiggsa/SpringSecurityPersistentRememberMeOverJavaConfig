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
    <p>
        <label for="username">Username:</label>
        <input type="text" id="username" name="username"/>
    </p>
    <p>
        <label for="password">Password:</label>
        <input type="password" id="password" name="password"/>
    </p>
    <p>
        <label for="remember-me">Remember Me</label>
    </p>
    <input type="checkbox" id="remember-me" name="remember-me"/>

    <input type="hidden"
           name="${_csrf.parameterName}"
           value="${_csrf.token}"/>
    <button type="submit">Sign In</button>
</form>

</body>
</html>