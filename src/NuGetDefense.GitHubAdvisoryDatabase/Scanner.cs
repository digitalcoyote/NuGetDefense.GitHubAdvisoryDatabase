using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Net.WebSockets;
using System.Threading.Tasks;
using GraphQL;
using GraphQL.Client.Http;
using GraphQL.Client.Serializer.SystemTextJson;
using NuGet.Versioning;
using NuGetDefense.Core;

namespace NuGetDefense.GitHubAdvisoryDatabase
{
    public class Scanner
    {
        private readonly bool BreakIfCannotRun;
        private readonly string NugetFile;
        private readonly string _apiToken;

        public Scanner(string nugetFile, string passToken, bool breakIfCannotRun = false)
        {
            NugetFile = nugetFile;
            BreakIfCannotRun = breakIfCannotRun;
            _apiToken = passToken;
        }
        public Dictionary<string, Dictionary<string, Vulnerability>> GetVulnerabilitiesForPackages(
            IEnumerable<NuGetPackage> pkgs,
            Dictionary<string, Dictionary<string, Vulnerability>>? vulnDict = null)
        {
            vulnDict ??= new();

            try
            {

                foreach (var pkg in pkgs)
                {
                    var githubResponse = QueryVulnerabilitiesForPacakgeId(pkg.Id).Result.Data;
                    if (githubResponse.SecurityVulnerabilities.TotalCount <= 0) continue;

                    if (!vulnDict.ContainsKey(pkg.Id)) vulnDict.Add(pkg.Id, new());
                    for (var index = 0; index < githubResponse.SecurityVulnerabilities.Nodes.Length; index++)
                    {
                        var securityAdvisoryNode = githubResponse.SecurityVulnerabilities.Nodes[index];
                        var vulnerableVersionRange = VersionRange.Parse(ToNugetRange(securityAdvisoryNode.VulnerableVersionRange));
                        if (!vulnerableVersionRange.Satisfies(new(pkg.Version))) continue;

                        var cve = securityAdvisoryNode.Advisory.Identifiers.FirstOrDefault(id => vulnDict.ContainsKey(id.Value));
                        if (cve != null) continue;

                        cve = securityAdvisoryNode.Advisory.Identifiers[0];
                        vulnDict[pkg.Id].Add(cve.Value, securityAdvisoryNode.Advisory.ToNuGetDefenseVulnerability());
                    }
                }

            }
            catch (Exception e)
            {
                Console.WriteLine(
                    $"{NugetFile} : {(BreakIfCannotRun ? "Error" : "Warning")} : NuGetDefense : GitHub Advisory Database scan failed with exception: {e}");
            }

            return vulnDict;
            }

        /// <summary>
        /// Converts the ranges reported by GitHub into NuGet Ranges
        /// </summary>
        /// <param name="vulnerableVersionRange"></param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        private string ToNugetRange(string vulnerableVersionRange)
        {
            var parts = vulnerableVersionRange.Split(' ');
            return parts[0] switch
            {
                "<" => $"(,{parts[1]})",
                "<=" => $"(,{parts[1]}]",
                ">" => $"({parts[1]},)",
                ">=" => $"[{parts[1]},)",
                _ => vulnerableVersionRange
            };
        }

        private async Task<GraphQLResponse<Data>> QueryVulnerabilitiesForPacakgeId(string packageid)
        {
            var graphQLClient = new GraphQLHttpClient("https://api.github.com/graphql", new SystemTextJsonSerializer());
            
            graphQLClient.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd(userAgent);
            graphQLClient.HttpClient.DefaultRequestHeaders.Authorization = new("bearer", _apiToken);
            var vulnQuery = @"query($package:String) {
  securityVulnerabilities(
    ecosystem: NUGET
    first: 100
    package: $package
    orderBy: { field: UPDATED_AT, direction: DESC }
  ) {
    nodes {
      advisory {
        references{
          url
        }
        identifiers {
          type
          value
        }
        cvss {
          vectorString
          score
        }
        cwes(first: 100) {
          edges {
            node {
              id
            }
          }
        }
        summary
        severity
        
      }
      vulnerableVersionRange
      package {
        name
      }
    }
    totalCount
  }
}";

            var req = new GraphQLRequest
            {
                Query = vulnQuery,
                Variables = new { package = packageid }
            };

            return await graphQLClient.SendQueryAsync<Data>(req);
        }

        private const string? userAgent = @"NuGetDefense.GitHubAdvisoryDatabase/1.0.0 (https://github.com/digitalcoyote/NuGetDefense.GitHubAdvisoryDatabase/blob/master/README.md)";
    }
}