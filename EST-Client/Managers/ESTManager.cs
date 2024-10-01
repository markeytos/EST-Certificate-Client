using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using EST_Client.Models;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.X509;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Utilities.Collections;
using Org.BouncyCastle.X509.Extension;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace EST_Client.Managers;

public class ESTManager
{
    
    private ILogger _logger;
    private HttpClient _httpClient;
    public ESTManager(string? appInsightsConnectionString, X509Certificate2 clientCertificate)
    {
        IServiceProvider  serviceProvider = CreateServices(appInsightsConnectionString, clientCertificate);
        _logger = serviceProvider.GetRequiredService<ILogger<ESTManager>>();
        var httpClientFactory = serviceProvider.GetRequiredService<IHttpClientFactory>();
        _httpClient = httpClientFactory.CreateClient("ESTClient");
    }

    public async Task<int> RenewCertificateAsync(X509Certificate2? existingCertificate, string? estUrl)
    {
        //validate input
        ArgumentNullException.ThrowIfNull(existingCertificate);
        ArgumentException.ThrowIfNullOrWhiteSpace(estUrl);
        try
        {
            _logger.LogInformation("Renewing certificate");
#if DEBUG
            //Let's test the connection (This is just to debug that we can reach the server with client certificate and should be removed for production)
            int index = estUrl.IndexOf('/', estUrl.IndexOf("//", StringComparison.Ordinal) + 2);
            HttpResponseMessage testResponse = await _httpClient.GetAsync(estUrl[..index] + "/health/certificate");
            if (testResponse.IsSuccessStatusCode)
            {
                string responseString = await testResponse.Content.ReadAsStringAsync();
                Console.WriteLine("Connected to the EST server " + responseString);
            }
            else
            {
                Console.WriteLine("Failed to connect to the EST server " + testResponse.StatusCode + " " + await testResponse.Content.ReadAsStringAsync());
            }
#endif
            //Get Server Certificates
            HttpResponseMessage response = await _httpClient.GetAsync(estUrl + "/cacerts");
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogError("Failed to get server certificates " + response.StatusCode + " " + await response.Content.ReadAsStringAsync());
                return 1;
            }
            string caResponseString = await response.Content.ReadAsStringAsync();
            CmsSignedData cmsData = ConvertBase64StringToCmsSignedData(caResponseString);
            List<X509Certificate2> serverCertificates = GetCertificatesFromCmsSignedData(cmsData);
            //Check if the existing certificate is signed by the server CAs
            bool isSignedByServerCa = IsCertificateSignedByServerCa(existingCertificate, serverCertificates);
            if (!isSignedByServerCa)
            {
                _logger.LogError("Certificate is not signed by the server CA");
                return 1;
            }
            //Create a new certificate request
            var (csrBytes, rsaKey) = CreateCsrWithNewKey(existingCertificate);
            string csrBase64 = Convert.ToBase64String(csrBytes);
            //Send the request to the EST server
            StringContent content = new(csrBase64, Encoding.UTF8, "application/pkcs10"); 
            HttpResponseMessage csrResponse = await _httpClient.PostAsync(estUrl + "/simpleenroll", content);
            if (!csrResponse.IsSuccessStatusCode)
            {
                string responseString = await csrResponse.Content.ReadAsStringAsync();
                _logger.LogError("Failed to send CSR to the EST server " + csrResponse.StatusCode + " " + responseString);
                return 1;
            }
            string certResponseString = await csrResponse.Content.ReadAsStringAsync();
            CmsSignedData certCmsData = ConvertBase64StringToCmsSignedData(certResponseString);
            X509Certificate2? newCertificate = GetCertificatesFromCmsSignedData(certCmsData).FirstOrDefault();
            if(newCertificate == null)
            {
                _logger.LogError("Failed to get new certificate from the EST server");
                return 1;
            }
            //Save new certificate with private key
            X509Certificate2 newCertificateWithPrivateKey = new (newCertificate.RawData);
            newCertificateWithPrivateKey = newCertificateWithPrivateKey.CopyWithPrivateKey(rsaKey);
            await File.WriteAllBytesAsync("newCertificate.pfx", newCertificateWithPrivateKey.Export(X509ContentType.Pfx,""));
            return 0;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to renew certificate");
            return 1;
        }
    }
    
     private static (byte[] csrBytes, RSA rsaKey) CreateCsrWithNewKey(X509Certificate2 cert)
    {
        // Extract the subject name from the existing certificate
        var subjectName = cert.Subject;

        // Extract the Subject Alternative Names (SANs)
        var sanBuilder = new SubjectAlternativeNameBuilder();
        List<X509SubjectAlternativeName> subjectAlternativeNames = GetSubjectAlternativeNames(cert);
        foreach (var san in subjectAlternativeNames)
        {
            switch (san.Type)
            {
                case SANTypes.DNSName:
                    sanBuilder.AddDnsName(san.Value);
                    break;
                case SANTypes.IPAddress:
                    sanBuilder.AddIpAddress(IPAddress.Parse(san.Value));
                    break;
                case SANTypes.Rfc822Name:
                    sanBuilder.AddEmailAddress(san.Value);
                    break;
                case SANTypes.URI:
                    sanBuilder.AddUri(new Uri(san.Value));
                    break;
                case SANTypes.UPN:
                    sanBuilder.AddUserPrincipalName(san.Value);
                    break;
            }
        }

        // Extract EKUs (Extended Key Usages)
        List<Oid> ekuOids = new ();
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.37") // OID for EKU
            {
                var ekuExtension = (X509EnhancedKeyUsageExtension)extension;
                foreach (var eku in ekuExtension.EnhancedKeyUsages)
                {
                    ekuOids.Add(eku);
                }
            }
        }

        // Extract Key Usages
        X509KeyUsageFlags keyUsages = X509KeyUsageFlags.None;
        foreach (var extension in cert.Extensions)
        {
            if (extension.Oid?.Value == "2.5.29.15") // OID for Key Usage
            {
                var keyUsageExtension = (X509KeyUsageExtension)extension;
                keyUsages = keyUsageExtension.KeyUsages;
            }
        }

        // Generate a new RSA key pair (You can use ECDsa instead if needed)
        RSA rsa = RSA.Create(4096);

        // Create the Certificate Request
        var csr = new CertificateRequest(subjectName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        // Add SANs to the CSR
        csr.CertificateExtensions.Add(sanBuilder.Build());

        // Add EKUs to the CSR
        if (ekuOids.Count > 0)
        {
            var ekuExtension = new X509EnhancedKeyUsageExtension();
            foreach (var oid in ekuOids)
            {
                ekuExtension.EnhancedKeyUsages.Add(oid);
            }
            csr.CertificateExtensions.Add(ekuExtension);
        }

        // Add Key Usage to the CSR
        if (keyUsages != X509KeyUsageFlags.None)
        {
            var keyUsageExtension = new X509KeyUsageExtension(keyUsages, critical: true);
            csr.CertificateExtensions.Add(keyUsageExtension);
        }

        // Create the CSR in DER format
        var csrBytes = csr.CreateSigningRequest();

        // Return both the CSR and the private key
        return (csrBytes, rsa);
    }
     
     private static List<X509SubjectAlternativeName> GetSubjectAlternativeNames(
        X509Certificate2 certificate
    )
    {
        var subjectAlternativeNames = new List<X509SubjectAlternativeName>();

        // Convert X509Certificate2 to Bouncy Castle X509Certificate
        var parser = new X509CertificateParser();
        var bcCert = parser.ReadCertificate(certificate.RawData);

        // Get the SubjectAlternativeNames extension
        var sanExtension = bcCert.GetExtensionValue(X509Extensions.SubjectAlternativeName);

        if (sanExtension != null)
        {
            var asn1Object = X509ExtensionUtilities.FromExtensionValue(sanExtension);
            var generalNames = GeneralNames.GetInstance(asn1Object);

            foreach (var generalName in generalNames.GetNames())
            {
                X509SubjectAlternativeName x509SubjectAlternativeName = new();
                switch (generalName.TagNo)
                {
                    case GeneralName.Rfc822Name:
                        x509SubjectAlternativeName.Type = SANTypes.Rfc822Name;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString();
                        break;
                    case GeneralName.DnsName:
                        x509SubjectAlternativeName.Type = SANTypes.DNSName;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString();
                        break;
                    case GeneralName.UniformResourceIdentifier:
                        x509SubjectAlternativeName.Type = SANTypes.URI;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString();
                        break;
                    case GeneralName.DirectoryName:
                        x509SubjectAlternativeName.Type = SANTypes.DirectoryName;
                        x509SubjectAlternativeName.Value = ((X509Name)generalName.Name).ToString();
                        break;
                    case GeneralName.IPAddress:
                        x509SubjectAlternativeName.Type = SANTypes.IPAddress;
                        x509SubjectAlternativeName.Value = string.Join(
                            ".",
                            ((DerOctetString)generalName.Name).GetOctets()
                        );
                        break;
                    case GeneralName.OtherName:
                        var sequence = Asn1Sequence.GetInstance(generalName.Name);
                        var oid = DerObjectIdentifier.GetInstance(sequence[0]);
                        if (oid.Id == "1.3.6.1.4.1.311.20.2.3") // OID for UPN
                        {
                            x509SubjectAlternativeName.Type = SANTypes.UPN;
                            var upn = DerUtf8String.GetInstance(
                                Asn1TaggedObject.GetInstance(sequence[1]).GetBaseObject()
                            );
                            x509SubjectAlternativeName.Value = upn.GetString();
                        }
                        else
                        {
                            x509SubjectAlternativeName.Type = SANTypes.OtherName;
                            x509SubjectAlternativeName.Value = generalName.Name.ToString();
                        }
                        break;
                    default:
                        x509SubjectAlternativeName.Type = SANTypes.Unknown;
                        x509SubjectAlternativeName.Value = generalName.Name.ToString();
                        break;
                }
                subjectAlternativeNames.Add(x509SubjectAlternativeName);
            }
        }
        return subjectAlternativeNames;
    }
    
    private bool IsCertificateSignedByServerCa(X509Certificate2 existingCertificate, List<X509Certificate2> serverCertificates)
    {
        X509Chain chain = new();
        foreach (X509Certificate2 serverCertificate in serverCertificates)
        {
            chain.ChainPolicy.CustomTrustStore.Add(serverCertificate);
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        }
#if DEBUG
        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck; // not checking revocation in debug mode
#endif
        bool trust = chain.Build(existingCertificate);
        if (!trust)
        {
            Console.WriteLine("Error validating CA Certificates: " + chain.ChainStatus[0].StatusInformation);
        }
        return trust;
    }
    
    private static List<X509Certificate2> GetCertificatesFromCmsSignedData(CmsSignedData cmsSignedData)
    {
        IStore<X509Certificate> certStore = cmsSignedData.GetCertificates();
        List<X509Certificate> certificates = certStore.EnumerateMatches(null).ToList();
        return certificates
            .Select(cert => new X509Certificate2(cert.GetEncoded()))
            .ToList();
    }
    
    private static CmsSignedData ConvertBase64StringToCmsSignedData(string base64String)
    {
        // Step 1: Decode the Base64 string back to bytes
        byte[] cmsDataBytes = Convert.FromBase64String(base64String);
        // Step 2: Create a CMSSignedData object from the byte array
        CmsSignedData cmsSignedData = new CmsSignedData(cmsDataBytes);
        return cmsSignedData;
    }

    private IServiceProvider CreateServices(string? appInsightsKey, X509Certificate2? clientCertificate)
    {
        IServiceCollection services = new ServiceCollection();
        services.AddLogging(builder =>
        {
            if (!string.IsNullOrWhiteSpace(appInsightsKey))
            {
                builder.AddApplicationInsights(
                    configureTelemetryConfiguration: (config) =>
                        config.ConnectionString = appInsightsKey,
                    configureApplicationInsightsLoggerOptions: (_) => { }
                );
            }
            #if WINDOWS
            builder.AddEventLog();
            #endif
        });
        if(clientCertificate == null)
        {
            services
                .AddHttpClient<HttpClient>("ESTClient")
                .AddStandardResilienceHandler(options =>
                {
                    options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(60);
                    options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(60);
                    options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(20);
                });
        }
        else
        {
            services
                .AddHttpClient<HttpClient>("ESTClient")
                .ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler
                {
                    ClientCertificates = { clientCertificate },
                })
                .AddStandardResilienceHandler(options =>
                {
                    options.TotalRequestTimeout.Timeout = TimeSpan.FromSeconds(60);
                    options.CircuitBreaker.SamplingDuration = TimeSpan.FromSeconds(60);
                    options.AttemptTimeout.Timeout = TimeSpan.FromSeconds(20);
                });
        }
       
        IServiceProvider serviceProvider = services.BuildServiceProvider();
        return serviceProvider;
    }
    
    

}