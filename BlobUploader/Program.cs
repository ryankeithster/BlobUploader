using Azure.Extensions.AspNetCore.Configuration.Secrets;
using Azure.Identity;
using Azure.Messaging.EventHubs;
using Azure.Messaging.EventHubs.Producer;
using Azure.Storage.Blobs;
using Microsoft.Extensions.Configuration;
using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace BlobUploader // Note: actual namespace depends on the project name.
{
    public class Program
    {
        static BlobContainerClient? blobContainerClient;
        static BlobClient? blobClient;
        static readonly string blobContainer = "video-frames";
        static readonly int sleepIntervalMs = 100;

        private static void GetAzureAppConfigurationValues(out string KeyVaultName, out string AzureADDirectoryID, out string AzureADApplicationID, out string Thumbprint)
        {
            // Parse appSetting.json
            ConfigurationBuilder builder = new ConfigurationBuilder();
            string temp = Directory.GetCurrentDirectory();
            builder.SetBasePath(Directory.GetCurrentDirectory());
            builder.AddJsonFile("appSettings.json", optional: false);
            IConfigurationRoot builtConfig = builder.Build();

            // Extract values from appSettings
            KeyVaultName = builtConfig["KeyVaultName"];
            AzureADDirectoryID = builtConfig["AzureADDirectoryId"];
            AzureADApplicationID = builtConfig["AzureADApplicationId"];
            Thumbprint = builtConfig["AzureADCertThumbprint"];
        }

        /// <summary>
        /// Get the specified secret value from the Azure Key Vault at the specified location.
        /// Applications that are not deployed in Azure can use an Application ID and an X.509 certificate to verify their identity with Azure.
        /// </summary>
        /// <param name="KeyVaultName"></param>
        /// <param name="AzureADDirectoryID"></param>
        /// <param name="AzureADApplicationID"></param>
        /// <param name="CertThumbprint"></param>
        /// <param name="SecretName"></param>
        /// <returns></returns>
        public static string GetSecretValueWithCertAndClientID(string KeyVaultName, string AzureADDirectoryID, string AzureADApplicationID, string CertThumbprint, string SecretName)
        {
            ConfigurationBuilder builder = new ConfigurationBuilder();

            using var store = new X509Store(StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2Collection certs = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                CertThumbprint, false);

            builder.AddAzureKeyVault(new Uri($"https://{KeyVaultName}.vault.azure.net/"),
                                    new ClientCertificateCredential(AzureADDirectoryID, AzureADApplicationID, certs.OfType<X509Certificate2>().Single()),
                                    new KeyVaultSecretManager());
            IConfigurationRoot config = builder.Build();

            return config[SecretName];
        }

        static async Task Main()
        {
            string keyVaultName, azureADDirectoryID, azureADApplicationID, thumbprint, blobStorageConnectionString;

            // Get values from appSettings.json needed for authenticating with and reading from AKV
            GetAzureAppConfigurationValues(out keyVaultName, 
                out azureADDirectoryID, 
                out azureADApplicationID, 
                out thumbprint);

            // Get the blob storage connection string from AKV
            blobStorageConnectionString = 
                GetSecretValueWithCertAndClientID(keyVaultName, 
                azureADDirectoryID, 
                azureADApplicationID, 
                thumbprint, 
                "videoframe-blob-connection-string");

            blobContainerClient = new BlobContainerClient(blobStorageConnectionString, blobContainer);

            string[] blobNames = { "20211010_173728.jpg", "WIN_20220213_19_42_46_Pro.jpg", "WIN_20220213_19_42_50_Pro.jpg", "WIN_20220213_19_42_56_Pro.jpg" };

            string pattern = "*.jpg";
            string directory = @"C:\temp\video_frames";
            var dirInfo = new DirectoryInfo(directory);
            string blobName = string.Empty, prevBlobName = string.Empty;
            int timeToSleepMs = 0;

            while (true)
            {
                FileInfo? file = dirInfo.GetFiles(pattern).
                    OrderByDescending(f => f.LastWriteTime).
                    FirstOrDefault();

                if (file != null)
                {
                    blobName = file.Name;
                    timeToSleepMs = sleepIntervalMs;

                    if (blobName != prevBlobName)
                    {
                        prevBlobName = blobName;

                        byte[] fileBytes = new byte[file.Length];

                        using (FileStream fs = File.OpenRead(file.FullName))
                        {
                            fs.Read(fileBytes, 0, (int)file.Length);
                        }

                        // Read the contents of the file to be uploaded
                        //byte[] fileBytes = File.ReadAllBytes(file.FullName);

                        blobClient = blobContainerClient.GetBlobClient(blobName);

                        DateTime uploadStart = DateTime.Now;

                        // Wait for the blob to be uploaded
                        await blobClient.UploadAsync(new BinaryData(fileBytes), true);

                        DateTime uploadEnd = DateTime.Now;

                        TimeSpan deltaTime = uploadEnd.Subtract(uploadStart);
                        timeToSleepMs = sleepIntervalMs - (int)deltaTime.TotalMilliseconds;

                        if (timeToSleepMs <= 0)
                        {
                            timeToSleepMs = 1;
                        }
                    }

                    Thread.Sleep(timeToSleepMs);
                }
            }

            /*foreach (var blobName in blobNames)
            {
                blobClient = blobContainerClient.GetBlobClient(blobName);

                // Read the contents of the file to be uploaded
                byte[] fileBytes = File.ReadAllBytes(@"Blobs\" + blobName);

                // Wait for the blob to be uploaded
                await blobClient.UploadAsync(new BinaryData(fileBytes), true);

                Thread.Sleep(1000);
            }*/

        }
    }
}
