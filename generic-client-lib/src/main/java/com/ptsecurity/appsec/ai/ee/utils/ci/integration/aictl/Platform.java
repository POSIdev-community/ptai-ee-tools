package com.ptsecurity.appsec.ai.ee.utils.ci.integration.aictl;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.Arrays;
import java.util.Locale;

@Getter
@RequiredArgsConstructor
public enum Platform {
    LINUX_AMD64("linux", "amd64", false),
    LINUX_ARM64("linux", "arm64", false),
    DARWIN_AMD64("darwin", "amd64", false),
    DARWIN_ARM64("darwin", "arm64", false),
    WINDOWS_AMD64("windows", "amd64", true);

    @NonNull
    private final String os;

    @NonNull
    private final String arch;

    private final boolean windows;

    public String fileName() {
        return windows ? "aictl.exe" : "aictl";
    }

    public String resourcePath() {
        return "/aictl/" + os + "-" + arch + "/" + fileName();
    }

    public static Platform detect(@NonNull final String osName, @NonNull final String osArch) throws GenericException {
        String name = osName.toLowerCase(Locale.ROOT);
        String arch = osArch.toLowerCase(Locale.ROOT);

        String os;
        if (name.contains("win")){
            os = "windows";
        } else if (name.contains("mac") || name.contains("darwin")) {
            os = "darwin";
        } else if (name.contains("nux") || name.contains("nix")) {
            os = "linux";
        } else {
            throw GenericException.raise(
                    "aictl does not support this operating system",
                    new IllegalArgumentException(osName));
        }

        String normalizedArch;
        if ("amd64".equals(arch) || "x86_64".equals(arch) || "x64".equals(arch)) {
            normalizedArch = "amd64";
        } else if ("aarch64".equals(arch) || "arm64".equals(arch)) {
            normalizedArch = "arm64";
        } else {
            throw GenericException.raise(
                    "aictl does not support this CPU architecture",
                    new IllegalArgumentException(osArch));
        }

        final String finalOs = os;
        return Arrays.stream(values())
                .filter(p -> p.os.equals(finalOs) && p.arch.equals(normalizedArch))
                .findFirst()
                .orElseThrow(() -> GenericException.raise(
                        "No aictl binary is published for this platform",
                        new IllegalArgumentException(osName + " / " + osArch)));
    }

    public static Platform current() throws GenericException {
        return detect(System.getProperty("os.name", ""), System.getProperty("os.arch", ""));
    }
}
