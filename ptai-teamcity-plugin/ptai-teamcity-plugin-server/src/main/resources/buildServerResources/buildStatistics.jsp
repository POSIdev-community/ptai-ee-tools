<%@ include file="common.jsp" %>
<jsp:useBean id="ptaiSteps" type="java.util.List" scope="request"/>
<jsp:useBean id="ptaiLabels" type="java.util.Map" scope="request"/>
<jsp:useBean id="ptaiBuildId" type="java.lang.Long" scope="request"/>

<bs:linkCSS dynamic="${true}">
    ${teamcityPluginResourcesPath}css/statistics.css
</bs:linkCSS>

<div class="ptai-statistics">
    <c:forEach var="step" items="${ptaiSteps}">
        <div class="ptai-step">
            <h2 class="ptai-step-title"><c:out value="${step.name}"/></h2>
            <c:choose>
                <c:when test="${step.incompatible}">
                    <p class="ptai-message"><c:out value="${ptaiLabels.incompatible}"/></p>
                </c:when>
                <c:otherwise>
                    <c:forEach var="table" items="${step.tables}">
                        <h3 class="ptai-table-title"><c:out value="${table.title}"/></h3>
                        <table class="ptai-table">
                            <c:forEach var="row" items="${table.rows}">
                                <tr class="ptai-${row.color}">
                                    <td class="ptai-table-label"><c:out value="${row.label}"/></td>
                                    <td><c:out value="${row.value}"/></td>
                                </tr>
                            </c:forEach>
                        </table>
                    </c:forEach>

                    <h3 class="ptai-table-title"><c:out value="${ptaiLabels.breakdown}"/></h3>
                    <c:choose>
                        <c:when test="${step.charts == 'ASYNC'}">
                            <p class="ptai-message"><c:out value="${ptaiLabels.async}"/></p>
                        </c:when>
                        <c:when test="${step.charts == 'NO_DATA'}">
                            <p class="ptai-message"><c:out value="${ptaiLabels.noData}"/></p>
                        </c:when>
                        <c:when test="${step.charts == 'NO_ISSUES'}">
                            <p class="ptai-message"><c:out value="${ptaiLabels.noIssues}"/></p>
                        </c:when>
                        <c:otherwise>
                            <c:url var="chartsUrl" value="/ptai/statistics/build.html">
                                <c:param name="buildId" value="${ptaiBuildId}"/>
                                <c:param name="runnerId" value="${step.runnerId}"/>
                            </c:url>
                            <div class="ptai-build ptai-charts" data-ptai-url="<c:out value='${chartsUrl}'/>">
                                <div class="ptai-chart-cell ptai-wide">
                                    <h4><c:out value="${ptaiLabels.levels}"/></h4>
                                    <div class="ptai-chart" data-ptai-chart="levels"></div>
                                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                </div>
                                <div class="ptai-chart-cell">
                                    <h4><c:out value="${ptaiLabels.classes}"/></h4>
                                    <div class="ptai-chart ptai-pie" data-ptai-chart="classes"></div>
                                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                </div>
                                <div class="ptai-chart-cell">
                                    <h4><c:out value="${ptaiLabels.approvalStates}"/></h4>
                                    <div class="ptai-chart ptai-pie" data-ptai-chart="approvalStates"></div>
                                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                </div>
                                <c:if test="${!step.sbom}">
                                    <div class="ptai-chart-cell">
                                        <h4><c:out value="${ptaiLabels.suspected}"/></h4>
                                        <div class="ptai-chart ptai-pie" data-ptai-chart="suspected"></div>
                                        <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                    </div>
                                    <div class="ptai-chart-cell">
                                        <h4><c:out value="${ptaiLabels.scanModes}"/></h4>
                                        <div class="ptai-chart ptai-pie" data-ptai-chart="scanModes"></div>
                                        <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                    </div>
                                </c:if>
                                <div class="ptai-chart-cell ptai-wide">
                                    <h4><c:out value="${ptaiLabels.types}"/></h4>
                                    <div class="ptai-chart" data-ptai-chart="types"></div>
                                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noData}"/></div>
                                </div>
                            </div>
                        </c:otherwise>
                    </c:choose>
                </c:otherwise>
            </c:choose>
        </div>
    </c:forEach>
</div>

<%@ include file="statisticsInit.jsp" %>
