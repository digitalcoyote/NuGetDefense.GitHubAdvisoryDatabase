using System;
using NuGetDefense;
using NuGetDefense.GitHubAdvisoryDatabase;
using Xunit;

namespace GithubAdvisoryDatabaseClientTests
{
    public class UnitTest1
    {
        
        private readonly NuGetPackage[] _invulnerablePackages = { new()
            {
                Id = "log4net",
                Version = "2.0.8"
            }
        };

        // Needs a Test Project File committed and the test updated.
        // [Fact]
        public void ScanWorksWithTestProject()
        {
            var scanner = new Scanner("TestFile.csproj", "<Replace_With_API_Token>");
            var results = scanner.GetVulnerabilitiesForPackages(_invulnerablePackages);
            Assert.Single(results);
        }

        [Fact]
        public void ToNuGetRangeTest()
        {
            const string range = ">= 4.6.0, < 4.7.2";
            var ranges = Scanner.ToNugetRange(range);
            Assert.Equal(2, ranges.Length);

        }
    }
}