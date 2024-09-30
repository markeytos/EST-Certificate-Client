
using System.Security.Cryptography.X509Certificates;
using CommandLine;
using EST_Client.Managers;
using EST_Client.Models;

namespace EST_Client;

public class Program
{
    public static async Task<int> Main(string[] args)
    {
        
        RenewCertificateArgModel? certificateRenewalArgs = null;
        int result = Parser
            .Default.ParseArguments<
                RenewCertificateArgModel
            >(args)
            .MapResult(
                // Store validated arguments and return success code
                options =>
                {
                    certificateRenewalArgs = ValidateArguments(options);
                    return 0; // Return 0 to indicate successful parsing
                },
                // Return error code if parsing fails
                ProcessError
            );
        if (result == 0 && certificateRenewalArgs != null)
        {      
            if(!File.Exists(certificateRenewalArgs.CertificatePath))
            {
                Console.WriteLine("Certificate file does not exist");
                Environment.Exit(1);
            }
            X509Certificate2 existingCertificate = new(certificateRenewalArgs.CertificatePath,
                certificateRenewalArgs.Password);
            ESTManager certificateManager = new(certificateRenewalArgs.AppInsightsKey, existingCertificate);
            result = await certificateManager.RenewCertificateAsync(existingCertificate, certificateRenewalArgs.Url);
        }
        return result;
    }
    
    private static RenewCertificateArgModel ValidateArguments(RenewCertificateArgModel operation)
    {
        if (string.IsNullOrWhiteSpace(operation.CertificatePath))
        {
            Console.WriteLine("Certificate path is required");
            Environment.Exit(1);
        }
        if (string.IsNullOrWhiteSpace(operation.Url))
        {
            Console.WriteLine("URL is required");
            Environment.Exit(1);
        }
        return operation;
    }
    
    private static int ProcessError(IEnumerable<Error> errs)
    {
        return 1;
    }

}