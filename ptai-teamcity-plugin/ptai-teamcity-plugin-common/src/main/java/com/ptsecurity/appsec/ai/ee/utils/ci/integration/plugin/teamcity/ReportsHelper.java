package com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity;

import com.ptsecurity.appsec.ai.ee.scan.reports.Reports;
import com.ptsecurity.misc.tools.exceptions.GenericException;
import com.ptsecurity.appsec.ai.ee.utils.ci.integration.utils.ReportUtils;
import lombok.NonNull;
import org.apache.commons.lang3.StringUtils;

import java.util.Locale;
import java.util.Map;

import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.FALSE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Constants.TRUE;
import static com.ptsecurity.appsec.ai.ee.utils.ci.integration.plugin.teamcity.Params.*;

public class ReportsHelper {
    public static Reports convert(@NonNull final Map<String, String> data) throws GenericException {
        Reports res = new Reports();
        if (TRUE.equals(data.getOrDefault(REPORTING_REPORT, Defaults.REPORTING_REPORT))) {
            Reports.Report report = new Reports.Report();
            report.setFileName(data.get(REPORTING_REPORT_FILE));
            report.setTemplate(data.get(REPORTING_REPORT_TEMPLATE));
            if (FALSE.equals(data.getOrDefault(REPORTING_REPORT_DATAFLOW, Defaults.REPORTING_REPORT_DATAFLOW))) {
                report.setIncludeDfd(false);
            }
            if (FALSE.equals(data.getOrDefault(REPORTING_REPORT_SUMMARY, Defaults.REPORTING_REPORT_SUMMARY))) {
                report.setIncludeGlossary(false);
            }
            if (StringUtils.isNotEmpty(data.get(REPORTING_REPORT_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_REPORT_FILTER)));
            res.getReport().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_RAWDATA, Defaults.REPORTING_RAWDATA))) {
            Reports.RawData report = new Reports.RawData();
            report.setFileName(data.get(REPORTING_RAWDATA_FILE));
            if (StringUtils.isNotEmpty(data.get(REPORTING_RAWDATA_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_RAWDATA_FILTER)));
            res.getRaw().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_SARIF, Defaults.REPORTING_SARIF))) {
            Reports.Sarif report = new Reports.Sarif();
            report.setFileName(data.get(REPORTING_SARIF_FILE));
            if (StringUtils.isNotEmpty(data.get(REPORTING_SARIF_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_SARIF_FILTER)));
            res.getSarif().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_SONARGIIF, Defaults.REPORTING_SONARGIIF))) {
            Reports.SonarGiif report = new Reports.SonarGiif();
            report.setFileName(data.get(REPORTING_SONARGIIF_FILE));
            if (StringUtils.isNotEmpty(data.get(REPORTING_SONARGIIF_FILTER)))
                report.setFilters(ReportUtils.validateJsonFilter(data.get(REPORTING_SONARGIIF_FILTER)));
            res.getSonarGiif().add(report);
        }
        if (TRUE.equals(data.getOrDefault(REPORTING_JSON, Defaults.REPORTING_JSON)))
            res.append(ReportUtils.validateJsonReports(data.get(REPORTING_JSON_SETTINGS)));

        return res;
    }

    public static String getDefaultTemplate() {
        return Reports.Locale.RU == getDefaultLocale()
                ? "Отчет по результатам сканирования"
                : "Scan results report";
    }

    private static Reports.Locale getDefaultLocale() {
        String country = System.getProperty("user.country");
        String language = System.getProperty("user.language");
        Locale locale = new Locale(language, country);
        if (locale.getLanguage().equalsIgnoreCase(Reports.Locale.RU.name()))
            return Reports.Locale.RU;
        else
            return Reports.Locale.EN;
    }
}
