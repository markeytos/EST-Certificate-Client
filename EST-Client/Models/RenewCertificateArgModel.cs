using CommandLine;

namespace EST_Client.Models;

[Verb("renew", HelpText = "Renews an existing certificate")]
public class RenewCertificateArgModel
{
    [Option(
            'c',
            "certificatePath",
            Required = true,
            HelpText = "Path to the certificate to renew"
        )]
    public string? CertificatePath { get; set; }
    [Option(
            'p',
            "password",
            Required = false,
            HelpText = "Certificate password"
        )]
    public string? Password { get; set; }
    [Option(
            "AppInsights",
            Required = false,
            HelpText = "Azure Application Insights connection string to send logs to"
        )]
    public string? AppInsightsKey { get; set; }

    [Option('u', "url", Required = true, HelpText = "EST URL from your EZCA CA")]
    public string? Url { get; set; }
    
}