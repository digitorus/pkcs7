import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.time.Instant;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.KEMRecipientInformation;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKEMRecipientId;
import org.bouncycastle.cms.jcajce.JceKEMRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.util.CollectionStore;
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
            case "encrypt":
                if (args.length != 4) {
                    throw new IllegalArgumentException("encrypt requires certificate, content, and output");
                }
                encrypt(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]));
                break;
            case "decrypt":
                if (args.length != 5) {
                    throw new IllegalArgumentException("decrypt requires certificate, key, CMS, and output");
                }
                decrypt(Path.of(args[1]), Path.of(args[2]), Path.of(args[3]), Path.of(args[4]));
                break;
            case "composite-sign":
                if (args.length != 4) {
                    throw new IllegalArgumentException("composite-sign requires algorithm, content, and output directory");
                }
                signComposite(args[1], Path.of(args[2]), Path.of(args[3]));
                break;
            default:
                throw new IllegalArgumentException("unknown command: " + args[0]);
        }
    }

    private static void signComposite(String algorithm, Path contentPath, Path outputDir) throws Exception {
        Files.createDirectories(outputDir);
        byte[] content = Files.readAllBytes(contentPath);

        KeyPairGenerator compositeGenerator = KeyPairGenerator.getInstance(algorithm, PROVIDER);
        KeyPair signerKey = compositeGenerator.generateKeyPair();
        SubjectPublicKeyInfo signerSPKI = SubjectPublicKeyInfo.getInstance(
            ASN1Primitive.fromByteArray(signerKey.getPublic().getEncoded()));

        KeyPairGenerator issuerGenerator = KeyPairGenerator.getInstance("RSA");
        issuerGenerator.initialize(2048);
        KeyPair issuerKey = issuerGenerator.generateKeyPair();
        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
            new X500Name("CN=BC composite CMS test issuer"), BigInteger.ONE,
            Date.from(Instant.parse("2026-01-01T00:00:00Z")),
            Date.from(Instant.parse("2036-01-01T00:00:00Z")),
            new X500Name("CN=" + algorithm), signerSPKI);
        certificateBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        certificateBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        ContentSigner issuerSigner = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(PROVIDER).build(issuerKey.getPrivate());
        X509CertificateHolder signerCertificate = certificateBuilder.build(issuerSigner);

        SubjectPublicKeyInfo issuerSPKI = SubjectPublicKeyInfo.getInstance(
            ASN1Primitive.fromByteArray(issuerKey.getPublic().getEncoded())
        );

        X500Name issuerName = new X500Name("CN=BC composite CMS test issuer");

        X509v3CertificateBuilder issuerBuilder = new X509v3CertificateBuilder(
            issuerName,
            BigInteger.valueOf(2),
            Date.from(Instant.parse("2026-01-01T00:00:00Z")),
            Date.from(Instant.parse("2036-01-01T00:00:00Z")),
            issuerName,
            issuerSPKI
        );

        issuerBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        issuerBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));

        ContentSigner caSigner = new JcaContentSignerBuilder("SHA256withRSA")
            .setProvider(PROVIDER)
            .build(issuerKey.getPrivate());

        X509CertificateHolder issuerCertificate = issuerBuilder.build(caSigner);

        Files.write(outputDir.resolve("issuer.der"), issuerCertificate.getEncoded());

        for (boolean detached : new boolean[]{false, true}) {
            for (boolean direct : new boolean[]{false, true}) {
                ContentSigner contentSigner = new JcaContentSignerBuilder(algorithm)
                    .setProvider(PROVIDER).build(signerKey.getPrivate());
                JcaSignerInfoGeneratorBuilder signerBuilder = new JcaSignerInfoGeneratorBuilder(
                    new JcaDigestCalculatorProviderBuilder().setProvider(PROVIDER).build());
                signerBuilder.setDirectSignature(direct);
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                generator.addSignerInfoGenerator(signerBuilder.build(contentSigner, signerCertificate));
                generator.addCertificates(new CollectionStore<X509CertificateHolder>(
                    Collections.singletonList(signerCertificate)));
                CMSSignedData signedData = generator.generate(
                    new CMSProcessableByteArray(content), !detached);
                byte[] encoded = signedData.getEncoded();

                CMSSignedData parsed = detached
                    ? new CMSSignedData(new CMSProcessableByteArray(content), encoded)
                    : new CMSSignedData(encoded);
                if (parsed.getSignerInfos().size() != 1) {
                    throw new IllegalStateException("expected one composite CMS signer");
                }
                SignerInformation signer = parsed.getSignerInfos().getSigners().iterator().next();
                if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder()
                        .setProvider(PROVIDER).build(signerCertificate))) {
                    throw new IllegalStateException("BC composite self-check failed: " + algorithm);
                }

                String filename = (detached ? "detached" : "embedded")
                    + "-" + (direct ? "direct" : "attributes") + ".der";
                Files.write(outputDir.resolve(filename), encoded);
            }
        }
    }

    private static void sign(Path certificatePath, Path keyPath, Path contentPath, Path outputPath,
                             boolean detached, boolean direct, String keyAlgorithm,
                             String signatureAlgorithm) throws Exception {
        X509Certificate certificate = loadCertificate(certificatePath);
        PrivateKey privateKey = loadPrivateKey(keyPath, keyAlgorithm);
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

    private static void encrypt(Path certificatePath, Path contentPath, Path outputPath) throws Exception {
        X509Certificate certificate = loadCertificate(certificatePath);
        byte[] content = Files.readAllBytes(contentPath);

        CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
        generator.addRecipientInfoGenerator(new JceKEMRecipientInfoGenerator(certificate, CMSAlgorithm.AES256_WRAP)
            .setProvider(PROVIDER)
            .setKDF(CMSAlgorithm.SHA256_HKDF));
        CMSEnvelopedData envelopedData = generator.generate(
            new CMSProcessableByteArray(content),
            new JceCMSContentEncryptorBuilder(CMSAlgorithm.AES256_CBC).setProvider(PROVIDER).build());
        Files.write(outputPath, envelopedData.getEncoded());
    }

    private static void decrypt(Path certificatePath, Path keyPath, Path cmsPath, Path outputPath) throws Exception {
        X509Certificate certificate = loadCertificate(certificatePath);
        PrivateKey privateKey = loadPrivateKey(keyPath, "ML-KEM");
        CMSEnvelopedData envelopedData = new CMSEnvelopedData(Files.readAllBytes(cmsPath));
        RecipientInformationStore recipients = envelopedData.getRecipientInfos();
        if (recipients.size() != 1) {
            throw new IllegalStateException("expected exactly one recipient, got " + recipients.size());
        }
        RecipientInformation recipient = recipients.get(new JceKEMRecipientId(certificate));
        if (!(recipient instanceof KEMRecipientInformation)) {
            throw new IllegalStateException("expected a matching KEM recipient");
        }
        byte[] content = recipient.getContent(
            new JceKEMEnvelopedRecipient(privateKey).setProvider(PROVIDER));
        Files.write(outputPath, content);
    }

    private static X509Certificate loadCertificate(Path certificatePath) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509", PROVIDER);
        try (var input = Files.newInputStream(certificatePath)) {
            return (X509Certificate) factory.generateCertificate(input);
        }
    }

    private static PrivateKey loadPrivateKey(Path keyPath, String algorithm) throws Exception {
        return KeyFactory.getInstance(algorithm, PROVIDER).generatePrivate(
            new PKCS8EncodedKeySpec(Files.readAllBytes(keyPath)));
    }
}
