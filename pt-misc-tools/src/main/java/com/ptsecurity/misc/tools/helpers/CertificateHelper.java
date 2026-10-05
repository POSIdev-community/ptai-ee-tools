package com.ptsecurity.misc.tools.helpers;

import com.ptsecurity.misc.tools.exceptions.GenericException;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Slf4j
public class CertificateHelper {
    /**
     * Regular expression to extract certificate data from PEM-encoded file
     */
    protected static final Pattern parse = Pattern.compile("(?m)(?s)^-+BEGIN ([^-]+)-+$([^-]*)^-+END \\1-+$");

    /**
     * Method parses PEM-encoded string and fills resulting array with certificates
     * @param pem
     * @return
     * @throws GenericException
     */
    public static List<X509Certificate> readPem(@NonNull final String pem) throws CertificateException {
        Matcher match = parse.matcher(new String(pem.getBytes(), StandardCharsets.ISO_8859_1));
        List<X509Certificate> res = new ArrayList<>();
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        while (match.find()) {
            byte[] binaryContent = Base64.getMimeDecoder().decode(match.group(2));
            if (!"CERTIFICATE".equalsIgnoreCase(match.group(1))) continue;
            Certificate certificate = cf.generateCertificate(new ByteArrayInputStream(binaryContent));
            if (certificate instanceof X509Certificate)
                if (certificate.getPublicKey() instanceof RSAPublicKey)
                    res.add((X509Certificate) certificate);
        }
        return res;
    }
}
