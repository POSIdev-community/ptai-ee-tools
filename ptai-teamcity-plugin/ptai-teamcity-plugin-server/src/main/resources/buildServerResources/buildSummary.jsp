<%@ include file="common.jsp" %>
<jsp:useBean id="ptaiSteps" type="java.util.List" scope="request"/>
<jsp:useBean id="ptaiLabels" type="java.util.Map" scope="request"/>

<c:forEach var="step" items="${ptaiSteps}">
    <div class="ptai-summary">
        <c:out value="${ptaiLabels.plugin}"/>:
        <c:out value="${step.incompatible ? ptaiLabels.incompatible : step.summary}"/>
    </div>
</c:forEach>
