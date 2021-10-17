// <auto-generated />
//
// To parse this JSON data, add NuGet 'Newtonsoft.Json' then do:
//
//    using GithubAdvisoryResponse;
//
//    var welcome = Welcome.FromJson(jsonString);

using System.Diagnostics;
using System.Linq;
using System.Text.Json.Serialization;
using NuGetDefense.Core;

namespace NuGetDefense.GitHubAdvisoryDatabase
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text.Json;

    public partial class GithubAdvisoryResponse
    {
        [JsonPropertyName("data")]
        public Data Data { get; set; }
    }

    public partial class Data
    {
        [JsonPropertyName("securityVulnerabilities")]
        public SecurityVulnerabilities SecurityVulnerabilities { get; set; }
    }

    public partial class SecurityVulnerabilities
    {
        [JsonPropertyName("nodes")]
        public NodeElement[] Nodes { get; set; }

        [JsonPropertyName("totalCount")]
        public long TotalCount { get; set; }
    }

    public partial class NodeElement
    {
        [JsonPropertyName("advisory")]
        public Advisory Advisory { get; set; }

        [JsonPropertyName("vulnerableVersionRange")]
        public string VulnerableVersionRange { get; set; }

        [JsonPropertyName("package")]
        public Package Package { get; set; }
    }

    public partial class Advisory
    {
        [JsonPropertyName("references")]
        public Reference[] References { get; set; }

        [JsonPropertyName("identifiers")]
        public Identifier[] Identifiers { get; set; }

        [JsonPropertyName("cvss")]
        public Cvss Cvss { get; set; }

        [JsonPropertyName("cwes")]
        public Cwes Cwes { get; set; }

        [JsonPropertyName("summary")]
        public string Summary { get; set; }

        [JsonPropertyName("severity")]
        public string Severity { get; set; }
    }

    public partial class Cvss
    {
        [JsonPropertyName("vectorString")]
        public string VectorString { get; set; }
        
        [JsonPropertyName("score")]
        public double? Score { get; set; }
    }

    public partial class Cwes
    {
        [JsonPropertyName("edges")]
        public Edge[] Edges { get; set; }
    }

    public partial class Edge
    {
        [JsonPropertyName("node")]
        public EdgeNode Node { get; set; }
    }

    public partial class EdgeNode
    {
        [JsonPropertyName("id")]
        public string Id { get; set; }
    }

    public partial class Identifier
    {
        [JsonPropertyName("type")]
        public string Type { get; set; }

        [JsonPropertyName("value")]
        public string Value { get; set; }
    }

    public partial class Reference
    {
        [JsonPropertyName("url")]
        public Uri Url { get; set; }
    }

    public partial class Package
    {
        [JsonPropertyName("name")]
        public string Name { get; set; }
    }

    public partial class Welcome
    {
        public static Welcome FromJson(string json) => JsonSerializer.Deserialize<Welcome>(json, new JsonSerializerOptions());
    }
}
