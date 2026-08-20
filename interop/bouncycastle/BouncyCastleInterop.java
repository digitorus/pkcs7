import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public final class BouncyCastleInterop {
    private static final String PROVIDER = BouncyCastleProvider.PROVIDER_NAME;

    private BouncyCastleInterop() {
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (args.length == 0) {
            throw new IllegalArgumentException("expected sign or verify command");
        }
        switch (args[0]) {
            case "sign":
                if (args.length != 9) {
                    throw new IllegalArgumentException(
                        "sign requires certificate, key, content, output, detached, direct, key algorithm, and signature algorithm");
                }
                sign(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]), Path.of(args[4]),
                    Boolean.parseBoolean(args[5]), Boolean.parseBoolean(args[6]), args[7], args[8]);
                break;
            case "verify":
                if (args.length != 4) {
                    throw new IllegalArgumentException("verify requires CMS, content, and detached");
                }
                verify(Path.of(args[1]), Path.of(args[2]), Boolean.parseBoolean(args[3]));
                break;
            default:
                throw new IllegalArgumentException("unknown command: " + args[0]);
        }
    }

    private static void sign(Path certificatePath, Path keyPath, Path contentPath, Path outputPath,
                             boolean detached, boolean direct, String keyAlgorithm,
                             String signatureAlgorithm) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", PROVIDER);
        X509Certificate certificate;
        try (var input = Files.newInputStream(certificatePath)) {
            certificate = (X509Certificate) factory.generateCertificate(input);
        }
        PrivateKey privateKey = KeyFactory.getInstance(keyAlgorithm, PROVIDER).generatePrivate(
            new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath)));
        byte[] content = Files.readAllBytes(contentPath);

        ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm)
            .setProvider(PROVIDER)
            .build(privateKey);
        JcaSignerInfoGeneratorBuilder signerBuilder = new JcaSignerInfoGeneratorBuilder(
            new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build());
        signerBuilder.setDirectSignature(direct);

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(signerBuilder.build(contentSigner, certificate));
        generator.addCertificates(new JcaCertStore(Collections.singletonList(certificate)));
        CMSSignedData signedData = generator.generate(new CMSProcessableByteArray(content), !detached);
        Files.write(outputPath, signedData.getEncoded());
    }

    // Bouncy Castle's SignerId implements the legacy raw Selector interface.
    @SuppressWarnings("unchecked")
    private static void verify(Path cmsPath, Path contentPath, boolean detached) throws Exception {
        byte[] encoded = Files.readAllBytes(cmsPath);
        byte[] content = Files.readAllBytes(contentPath);
        CMSSignedData signedData = detached
            ? new CMSSignedData(new CMSProcessableByteArray(content), encoded)
            : new CMSSignedData(encoded);

        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.size() != 1) {
            throw new IllegalStateException("expected exactly one signer, got " + signers.size());
        }
        SignerInformation signer = signers.iterator().next();
        Collection<?> certificates = signedData.getCertificates().getMatches(signer.getSID());
        if (certificates.size() != 1) {
            throw new IllegalStateException("expected exactly one matching certificate, got " + certificates.size());
        }
        Object match = certificates.iterator().next();
        if (!(match instanceof X509CertificateHolder)) {
            throw new IllegalStateException("matching certificate has unexpected type: " + match.getClass());
        }
        X509CertificateHolder certificate = (X509CertificateHolder) match;
        if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider(PROVIDER).build(certificate))) {
            throw new IllegalStateException("CMS signature verification failed");
        }
        if (!detached) {
            Object recovered = signedData.getSignedContent().getContent();
            if (!(recovered instanceof byte[]) || !java.util.Arrays.equals(content, (byte[]) recovered)) {
                throw new IllegalStateException("embedded content does not match");
            }
        }
    }
}
