using System.Text.Json;
namespace GpoRemediator.Domain;

public record FineGrainedPasswordRequest(string ScopeDn,string Name,int Precedence=100,
    int PasswordHistoryCount=24,int MinPasswordLength=14,int MinPasswordAgeDays=1,int MaxPasswordAgeDays=90,
    bool ComplexityEnabled=true,bool ReversibleEncryptionEnabled=false,int LockoutThreshold=5,
    int LockoutDurationMinutes=15,int LockoutObservationWindowMinutes=15);
public record FineGrainedPasswordPlan(string Id,string Actor,string ExecutionUser,string Domain,string DomainController,
    FineGrainedPasswordRequest Request,JsonElement Preview,string CreatedAt,string ConfigHash);
public record FineGrainedPasswordAction(string Confirmation);

public static class FineGrainedPasswordRules
{
    public static void Validate(FineGrainedPasswordRequest r){
        if(string.IsNullOrWhiteSpace(r.ScopeDn)||!r.ScopeDn.StartsWith("OU=",StringComparison.OrdinalIgnoreCase)||r.ScopeDn.Length>2048||r.ScopeDn.IndexOfAny(['\r','\n','\0'])>=0)
            throw new PolicyException("FGPP_OU_REQUIRED","Select a discovered user OU.");
        if(!System.Text.RegularExpressions.Regex.IsMatch(r.Name??"","^[A-Za-z][A-Za-z0-9_.-]{2,63}$")||r.Precedence<1||
            r.PasswordHistoryCount is <0 or >1024||r.MinPasswordLength is <0 or >255||r.MinPasswordAgeDays is <0 or >998||r.MaxPasswordAgeDays is <1 or >999||
            r.MinPasswordAgeDays>=r.MaxPasswordAgeDays||r.LockoutThreshold is <1 or >999||
            r.LockoutDurationMinutes is <1 or >99999||r.LockoutObservationWindowMinutes is <1 or >99999||r.LockoutObservationWindowMinutes>r.LockoutDurationMinutes)
            throw new PolicyException("FGPP_VALUES_INVALID","Review the policy name, precedence, password ages/length/history and lockout durations.");
    }
}
