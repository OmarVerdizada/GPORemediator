using System.Reflection;
using System.Text.RegularExpressions;

namespace GpoRemediator.Domain;

public static class OperatorBenchmark
{
    private sealed record Entry(string Code, string Level, string Title, string Group);
    public static BenchmarkControl[] Load()
    {
        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("GpoRemediator.Data.benchmark.json")
            ?? throw new InvalidOperationException("Operator benchmark catalog is missing.");
        using var reader = new StreamReader(stream);
        var entries = JsonDefaults.Deserialize<Entry[]>(reader.ReadToEnd());
        return entries.Select(e =>
        {
            var mappedId = e.Code switch { "2.2.3" => "cis-2.2.3", "2.3.1.3" => "sec-blank-password", "2.3.17.6" => "sec-uac", _ => null };
            var existing = Catalog.Controls.FirstOrDefault(c => c.Id == mappedId);
            if (existing is not null) return existing with {
                BenchmarkId = "CIS", BenchmarkVersion = "4.0.0 (operator supplied)", ControlId = e.Code,
                Title = e.Title, Level = e.Level, PolicyPath = e.Group
            };
            var expected = Regex.Match(e.Title, @"(?:is set to|to include) (.+?)(?: \((?:MS only|DC only|Automated|Manual)\)|$)");
            var duplicate = entries.Count(other => other.Code == e.Code) > 1;
            var id = "benchmark-" + e.Code + (duplicate ? "-" + PolicyValues.Hash(e.Title)[..8] : "");
            return new BenchmarkControl(id, "CIS", "4.0.0 (operator supplied)", e.Code,
                e.Title, "Operator-supplied benchmark entry; current compliance has not been scanned.", e.Level,
                false, "See licensed benchmark applicability", ["MemberServer"], PolicyType.UNSUPPORTED,
                e.Group, "", [], expected.Success ? expected.Groups[1].Value : "See control title",
                false, RestartRequirement.NOT_REQUIRED, false, false, [], [],
                "Bu parametr siyahıya əlavə edilib. Yoxlanmış remediation adapteri hələ yoxdur; avtomatik tətbiq bağlıdır." +
                (duplicate ? " Təqdim edilən mətndə bu kod iki fərqli parametrə verilib; benchmark kodu dəqiqləşdirilməlidir." : ""));
        }).ToArray();
    }
}
