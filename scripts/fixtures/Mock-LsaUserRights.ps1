# Test-only native API double. Never opens a real LSA policy handle.
Add-Type -TypeDefinition @'
using System;
namespace GpoRemediator.ReadOnly {
 public static class UserRightsV1 {
  public static Func<string,string[]> Probe;
  public static string[] Read(string name){if(Probe==null)throw new InvalidOperationException("LSA fixture was not configured");return Probe(name);}
 }
}
'@
