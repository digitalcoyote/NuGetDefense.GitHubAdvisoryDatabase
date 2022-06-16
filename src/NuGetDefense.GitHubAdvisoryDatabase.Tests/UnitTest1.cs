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
            var scanner = new Scanner("TestFile.csproj", "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");
            var results = scanner.GetVulnerabilitiesForPackages(InvulnerablePackages);
            Assert.True(results.Count == 1);

        }

        [Fact]
        public void ToNuGetRangeTest()
        {
            const string range = ">= 4.6.0, < 4.7.2";
            var ranges = Scanner.ToNugetRange(range);
            Assert.True(ranges.Length == 2);

        }
    }
}