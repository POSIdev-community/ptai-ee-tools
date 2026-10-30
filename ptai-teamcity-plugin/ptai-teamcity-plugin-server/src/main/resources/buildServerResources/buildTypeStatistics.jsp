<%@ include file="common.jsp" %>
<jsp:useBean id="ptaiBuildTypeId" type="java.lang.String" scope="request"/>
<jsp:useBean id="ptaiHasData" type="java.lang.Boolean" scope="request"/>
<jsp:useBean id="ptaiLabels" type="java.util.Map" scope="request"/>

<bs:linkCSS dynamic="${true}">
    ${teamcityPluginResourcesPath}css/statistics.css
</bs:linkCSS>

<div class="ptai-statistics">
    <c:choose>
        <c:when test="${!ptaiHasData}">
            <p class="ptai-message"><c:out value="${ptaiLabels.noScans}"/></p>
        </c:when>
        <c:otherwise>
            <c:url var="chartsUrl" value="/ptai/statistics/buildType.html">
                <c:param name="buildTypeId" value="${ptaiBuildTypeId}"/>
            </c:url>
            <div class="ptai-build-type ptai-charts" data-ptai-url="<c:out value='${chartsUrl}'/>">
                <div class="ptai-chart-cell ptai-wide">
                    <h4><c:out value="${ptaiLabels.levelTrend}"/></h4>
                    <div class="ptai-chart" data-ptai-chart="levelTrend"></div>
                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noScans}"/></div>
                </div>
                <div class="ptai-chart-cell">
                    <h4><c:out value="${ptaiLabels.levelHistory}"/></h4>
                    <div class="ptai-chart" data-ptai-chart="levels"></div>
                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noScans}"/></div>
                </div>
                <div class="ptai-chart-cell">
                    <h4><c:out value="${ptaiLabels.approvalStates}"/></h4>
                    <div class="ptai-chart" data-ptai-chart="approvalStates"></div>
                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noScans}"/></div>
                </div>
                <div class="ptai-chart-cell ptai-wide">
                    <h4><c:out value="${ptaiLabels.types}"/></h4>
                    <div class="ptai-chart" data-ptai-chart="types"></div>
                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noScans}"/></div>
                </div>
                <div class="ptai-chart-cell ptai-wide">
                    <h4><c:out value="${ptaiLabels.durations}"/></h4>
                    <div class="ptai-chart" data-ptai-chart="durations"></div>
                    <div class="ptai-no-data"><c:out value="${ptaiLabels.noScans}"/></div>
                </div>
            </div>
        </c:otherwise>
    </c:choose>
</div>

<%@ include file="statisticsInit.jsp" %>
