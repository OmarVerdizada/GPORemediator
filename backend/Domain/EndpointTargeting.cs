namespace GpoRemediator.Domain;

public static class EndpointTargeting
{
    public static string Resolve(string? configured, string[] hosts)
    {
        if(string.IsNullOrWhiteSpace(configured))return hosts.Length>0?"ExplicitHosts":"SelectedOu";
        if(configured is not ("SelectedOu" or "ExplicitHosts"))
            throw new PolicyException("INVALID_ENDPOINT_TARGETING","Choose selected OU or explicit endpoint hosts.");
        return configured;
    }
}
