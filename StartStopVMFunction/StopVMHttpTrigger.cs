using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.ResourceManager.Compute;
using Microsoft.Azure.Functions.Worker;
using Microsoft.Azure.Functions.Worker.Http;
using System.Net;
using Azure.Security.KeyVault.Secrets;

namespace StartStopVMFunction;

public class StopVMHttpTrigger
{
    private readonly ILogger<StopVMHttpTrigger> _logger;

    public StopVMHttpTrigger(ILogger<StopVMHttpTrigger> logger)
    {
        _logger = logger;
    }

    [Function("StopVMHttpTrigger")]
    public async Task<HttpResponseData> Run(
        [HttpTrigger(AuthorizationLevel.Function, "get")] HttpRequestData req)
    {


        var query = System.Web.HttpUtility.ParseQueryString(req.Url.Query);
        var vmName = query["vmName"];
        var resourceGroup = query["resourceGroup"];

        if (string.IsNullOrEmpty(vmName) || string.IsNullOrEmpty(resourceGroup))
        {
            var bad = req.CreateResponse(HttpStatusCode.BadRequest);
            await bad.WriteStringAsync("Please provide vmName and resourceGroup parameters");
            return bad;
        }

        try
        {
            var kvHelper = new KeyVaultHelper();
            var tenantId = await kvHelper.GetSecretAsync("remote-tenant-id");
            var clientId = await kvHelper.GetSecretAsync("remote-client-id");
            var clientSecret = await kvHelper.GetSecretAsync("remote-client-secret");
            var subscriptionId = await kvHelper.GetSecretAsync("remote-subscription-id");

            _logger.LogInformation($"Retrieved secrets from Key Vault for tenant: {tenantId} and subscription: {subscriptionId} and clientId: {clientId}");

            var credential = new ClientSecretCredential(tenantId, clientId, clientSecret);
            var armClient = new ArmClient(credential, subscriptionId);

            var subscription = await armClient.GetDefaultSubscriptionAsync();
            var resourceGroups = subscription.GetResourceGroups();
            var rg = await resourceGroups.GetAsync(resourceGroup);

            var vms = rg.Value.GetVirtualMachines();
            var vm = await vms.GetAsync(vmName);

            _logger.LogInformation($"Deallocating VM {vmName} in resource group {resourceGroup}");
            await vm.Value.DeallocateAsync(Azure.WaitUntil.Started);

            _logger.LogInformation($"VM {vmName} deallocated successfully");
            var okResponse = req.CreateResponse(HttpStatusCode.OK);
            await okResponse.WriteStringAsync($@"{{""message"":""VM {vmName} deallocated successfully"",""vmName"":""{vmName}"",""resourceGroup"":""{resourceGroup}"",""status"":""deallocated""}}");
            okResponse.Headers.Add("Content-Type", "application/json");
            return okResponse;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Error starting VM {vm}", vmName);
            var resp = req.CreateResponse(HttpStatusCode.InternalServerError);
            await resp.WriteStringAsync($"Failed to start VM: {ex.Message}");
            return resp;
        }
    }
}

public class KeyVaultHelper
{
    private readonly SecretClient _secretClient;
    private readonly bool _useKeyVault;

    public KeyVaultHelper()
    {
        var keyVaultUri = Environment.GetEnvironmentVariable("KeyVaultUri");
        _useKeyVault = !string.IsNullOrEmpty(keyVaultUri);

        if (_useKeyVault)
        {
            _secretClient = new SecretClient(
                new Uri(keyVaultUri),
                new DefaultAzureCredential()
            );
        }
    }

    public async Task<string> GetSecretAsync(string secretName)
    {
        if (_useKeyVault)
        {
            try
            {
                var secret = await _secretClient.GetSecretAsync(secretName);
                return secret.Value.Value;
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to retrieve secret '{secretName}' from Key Vault: {ex.Message}", ex);
            }
        }
        else
        {
            var value = Environment.GetEnvironmentVariable(secretName);
            if (string.IsNullOrEmpty(value))
            {
                throw new Exception($"Secret '{secretName}' not found in environment variables or Key Vault");
            }
            return value;
        }
    }
}
