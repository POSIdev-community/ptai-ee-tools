package com.ptsecurity.appsec.ai.ee;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.UUID;

@Getter
@AllArgsConstructor
public class ProjectInfo {
    private UUID id;
    private String name;
}
