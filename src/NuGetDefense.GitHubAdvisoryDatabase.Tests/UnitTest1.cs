using System;
using NuGetDefense;
using NuGetDefense.GitHubAdvisoryDatabase;
using Xunit;

namespace GithubAdvisoryDatabaseClientTests
{
    public class UnitTest1
    {
        
        private readonly NuGetPackage[] InvulnerablePackages = { new()
            {
                Id = "log4net",
                Version = "2.0.8"
            }
        };
        
        [Fact]
        public void Test1()
        {
            var scanner = new Scanner("TestFile.csproj", "Put Your Access Token Here");
            var results = scanner.GetVulnerabilitiesForPackages(InvulnerablePackages);
            Assert.True(results.Count == 1);

        }
    }
}