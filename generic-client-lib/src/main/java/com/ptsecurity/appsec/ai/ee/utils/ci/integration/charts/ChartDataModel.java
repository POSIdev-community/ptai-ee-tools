package com.ptsecurity.appsec.ai.ee.utils.ci.integration.charts;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ChartDataModel extends BaseJsonChartDataModel {
    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Legend {
        @NonNull
        @JsonProperty
        @Builder.Default
        public List<String> data = new ArrayList<>();
    }

    @NonNull
    @JsonProperty
    @Builder.Default
    protected Legend legend = Legend.builder().build();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Axis {
        @JsonProperty
        @Builder.Default
        protected List<String> data = new ArrayList<>();
    }

    // ECharts's stacked area chart data model uses "xAxis" and "yAxis"
    // names. But if we simply name field "xAxis" then Lombok's generated
    // getter will be named as getXAxis. During POJOPropertiesCollector.collectAll
    // call that getter will be recognized as matching to xaxis or XAxis field
    // name (it depends on USE_STD_BEAN_NAMING mapper feature) so that field
    // will be serialized twice; as xAxis and xaxis / XAxis. So we need to
    // xplicitly set JSON property name and use neutral field name
    @Builder.Default
    @JsonProperty("xAxis")
    protected List<Axis> xaxis = new ArrayList<>();

    @Builder.Default
    @JsonProperty("yAxis")
    protected List<Axis> yaxis = new ArrayList<>();

    @Getter
    @Setter
    @Builder
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Series {
        @JsonProperty
        protected String name;

        @Getter
        @Setter
        @Builder
        @JsonInclude(JsonInclude.Include.NON_NULL)
        public static class DataItem {
            @JsonProperty
            protected Long value;

            @Getter
            @Setter
            @Builder
            @JsonInclude(JsonInclude.Include.NON_NULL)
            public static class ItemStyle {
                @JsonProperty
                protected String color;
            }

            @JsonProperty
            protected ItemStyle itemStyle;
        }

        @JsonProperty
        @Builder.Default
        protected List<DataItem> data = new ArrayList<>();

        @JsonProperty
        protected DataItem.ItemStyle itemStyle;
    }

    @JsonProperty
    @Builder.Default
    protected List<Series> series = new ArrayList<>();
}
