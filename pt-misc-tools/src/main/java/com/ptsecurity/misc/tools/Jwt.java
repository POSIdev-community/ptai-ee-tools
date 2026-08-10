package com.ptsecurity.misc.tools;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.*;

import java.time.OffsetDateTime;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class Jwt {
    protected static final String HIDDEN_TOKEN = "${hidden}";

    @JsonProperty("accessToken")
    protected String accessToken;

    @JsonProperty("refreshToken")
    protected String refreshToken;

    @JsonProperty("expiredAt")
    protected OffsetDateTime expiredAt;

    @Override
    public String toString() {
        return "Jwt(accessToken=" + mask(accessToken)
                + ", refreshToken=" + mask(refreshToken)
                + ", expiredAt=" + expiredAt + ")";
    }

    protected static String mask(final String token) {
        return token == null ? "null" : HIDDEN_TOKEN;
    }
}
