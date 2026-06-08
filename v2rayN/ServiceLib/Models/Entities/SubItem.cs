namespace ServiceLib.Models.Entities;

[Serializable]
public class SubItem
{
    [PrimaryKey]
    public string Id { get; set; }

    public string Remarks { get; set; }

    public string Url { get; set; }

    public string MoreUrl { get; set; }

    public bool Enabled { get; set; } = true;

    public string UserAgent { get; set; } = string.Empty;

    /// <summary>
    /// Hardware identifier sent as the x-hwid header when fetching the subscription.
    /// Required by panels (e.g. Remnawave) that enforce an HWID device limit.
    /// When empty, no HWID headers are sent.
    /// </summary>
    public string? Hwid { get; set; }

    public int Sort { get; set; }

    public string? Filter { get; set; }

    public int AutoUpdateInterval { get; set; }

    public long UpdateTime { get; set; }

    public string? ConvertTarget { get; set; }

    public string? PrevProfile { get; set; }

    public string? NextProfile { get; set; }

    public int? PreSocksPort { get; set; }

    public string? Memo { get; set; }
}
