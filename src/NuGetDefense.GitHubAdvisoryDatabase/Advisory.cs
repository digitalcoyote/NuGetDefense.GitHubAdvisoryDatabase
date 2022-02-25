using System.Linq;
using NuGetDefense.Core;

namespace NuGetDefense.GitHubAdvisoryDatabase
{
    public partial class Advisory
    {
        public Vulnerability ToNuGetDefenseVulnerability()
        {
            var id = Identifiers.FirstOrDefault(Id => Id.Type == "CVE")?.Value ?? Identifiers[0].Value;
            var vector = Cvss.VectorString?.Split('/').FirstOrDefault(x => x.Split(':')[0] == "AV") ?? "";
            if (!string.IsNullOrWhiteSpace(vector)) vector = vector.Substring(3);

            var vectorType = vector switch
            {
                "L" => Vulnerability.AccessVectorType.LOCAL,
                "A" => Vulnerability.AccessVectorType.ADJACENT_NETWORK,
                "N" => Vulnerability.AccessVectorType.NETWORK,
                "P" => Vulnerability.AccessVectorType.PHYSICAL,
                _ => Vulnerability.AccessVectorType.UNSPECIFIED
            };
            var refs = References.Select(r => r.Url.ToString()).ToArray();
            var cwe = Cwes.Edges.Length > 0 ? Cwes.Edges[0].Node.Id : string.Empty;
            return new(id, Cvss.Score ?? -1, cwe, Summary, refs, vectorType, "");
        }
    }
}