namespace ServiceLib.Handler.Fmt;

public class V2rayFmt : BaseFmt
{
    private static readonly List<string> _proxyProtocols =
        ["vless", "vmess", "trojan", "shadowsocks", "hysteria"];

    /// <summary>
    /// Resolves an array of full Xray (v2ray) configurations into typed profiles.
    /// Used by panels (e.g. Remnawave) whose <c>/json</c> subscription returns one complete
    /// Xray config per server. Unlike <see cref="ResolveFullArray"/> (which imports each config
    /// as an opaque custom file), this extracts the proxy outbound into a normal typed profile so
    /// the address/port/transport/TLS are shown and protocols such as Hysteria2 run on the right core.
    /// Returns null when nothing could be converted, so callers can fall back to custom import.
    /// </summary>
    public static List<ProfileItem>? ResolveFullArrayTyped(string strData, string? subRemarks)
    {
        List<V2rayConfig>? configs;
        try
        {
            configs = JsonUtils.Deserialize<List<V2rayConfig>>(strData);
        }
        catch
        {
            return null;
        }
        if (configs is not { Count: > 0 })
        {
            return null;
        }

        var lstResult = new List<ProfileItem>();
        foreach (var config in configs)
        {
            var item = ResolveOutboundTyped(config, subRemarks);
            if (item != null)
            {
                lstResult.Add(item);
            }
        }

        return lstResult.Count > 0 ? lstResult : null;
    }

    private static ProfileItem? ResolveOutboundTyped(V2rayConfig config, string? subRemarks)
    {
        var outbound = config.outbounds?.FirstOrDefault(o => o.tag == "proxy")
            ?? config.outbounds?.FirstOrDefault(o => _proxyProtocols.Contains(o.protocol ?? string.Empty));
        if (outbound?.settings == null)
        {
            return null;
        }

        var item = new ProfileItem
        {
            Remarks = config.remarks ?? subRemarks ?? "v2ray_server",
        };

        switch (outbound.protocol)
        {
            case "vless":
            case "vmess":
                var vnext = outbound.settings.vnext?.FirstOrDefault();
                var user = vnext?.users?.FirstOrDefault();
                if (vnext == null || user == null)
                {
                    return null;
                }
                item.Address = vnext.address;
                item.Port = vnext.port;
                item.Password = user.id ?? string.Empty;
                if (outbound.protocol == "vless")
                {
                    item.ConfigType = EConfigType.VLESS;
                    item.SetProtocolExtra(item.GetProtocolExtra() with
                    {
                        VlessEncryption = user.encryption.IsNullOrEmpty() ? Global.None : user.encryption,
                        Flow = user.flow,
                    });
                }
                else
                {
                    item.ConfigType = EConfigType.VMess;
                    item.SetProtocolExtra(item.GetProtocolExtra() with
                    {
                        AlterId = (user.alterId ?? 0).ToString(),
                        VmessSecurity = user.security,
                    });
                }
                break;

            case "trojan":
                var trojanServer = outbound.settings.servers?.FirstOrDefault();
                if (trojanServer == null)
                {
                    return null;
                }
                item.ConfigType = EConfigType.Trojan;
                item.Address = trojanServer.address;
                item.Port = trojanServer.port;
                item.Password = trojanServer.password ?? string.Empty;
                break;

            case "shadowsocks":
                var ssServer = outbound.settings.servers?.FirstOrDefault();
                if (ssServer == null)
                {
                    return null;
                }
                item.ConfigType = EConfigType.Shadowsocks;
                item.Address = ssServer.address;
                item.Port = ssServer.port;
                item.Password = ssServer.password ?? string.Empty;
                item.SetProtocolExtra(item.GetProtocolExtra() with { SsMethod = ssServer.method });
                break;

            case "hysteria":
                // Hysteria2 expressed in Xray-style json (runs on sing-box, not xray).
                item.ConfigType = EConfigType.Hysteria2;
                item.Address = outbound.settings.address?.ToString() ?? string.Empty;
                item.Port = outbound.settings.port ?? 0;
                item.Password = outbound.streamSettings?.hysteriaSettings?.auth ?? string.Empty;
                break;

            default:
                return null;
        }

        if (item.Address.IsNullOrEmpty() || item.Port <= 0)
        {
            return null;
        }

        FillStreamSettings(item, outbound.streamSettings);
        return item;
    }

    private static void FillStreamSettings(ProfileItem item, StreamSettings4Ray? ss)
    {
        if (ss == null)
        {
            return;
        }

        // Transport / network (xray "tcp" is "raw" in v2rayN)
        var network = ss.network.TrimEx();
        if (network is "tcp" or "")
        {
            network = Global.DefaultNetwork;
        }
        if (item.ConfigType != EConfigType.Hysteria2)
        {
            item.Network = Global.Networks.Contains(network) ? network : Global.DefaultNetwork;
        }

        // Security (tls / reality / none)
        if (ss.security is Global.StreamSecurity or Global.StreamSecurityReality)
        {
            item.StreamSecurity = ss.security;
        }

        var tls = ss.security == Global.StreamSecurityReality ? ss.realitySettings : ss.tlsSettings;
        if (tls != null)
        {
            item.Sni = tls.serverName ?? string.Empty;
            item.Fingerprint = tls.fingerprint ?? string.Empty;
            item.Alpn = tls.alpn != null ? string.Join(",", tls.alpn) : string.Empty;
            if (tls.allowInsecure == true)
            {
                item.AllowInsecure = Global.StringTrue;
            }
            if (ss.security == Global.StreamSecurityReality)
            {
                item.PublicKey = tls.publicKey ?? string.Empty;
                item.ShortId = tls.shortId ?? string.Empty;
                item.SpiderX = tls.spiderX ?? string.Empty;
            }
        }

        var transport = item.GetTransportExtra();
        switch (network)
        {
            case nameof(ETransport.ws):
                transport = transport with { Host = ss.wsSettings?.host, Path = ss.wsSettings?.path };
                break;

            case nameof(ETransport.httpupgrade):
                transport = transport with { Host = ss.httpupgradeSettings?.host, Path = ss.httpupgradeSettings?.path };
                break;

            case nameof(ETransport.xhttp):
                transport = transport with
                {
                    Host = ss.xhttpSettings?.host,
                    Path = ss.xhttpSettings?.path,
                    XhttpMode = ss.xhttpSettings?.mode,
                    XhttpExtra = ss.xhttpSettings?.extra != null ? JsonUtils.Serialize(ss.xhttpSettings.extra) : null,
                };
                break;

            case nameof(ETransport.grpc):
                transport = transport with
                {
                    GrpcAuthority = ss.grpcSettings?.authority,
                    GrpcServiceName = ss.grpcSettings?.serviceName,
                    GrpcMode = ss.grpcSettings?.multiMode == true ? Global.GrpcMultiMode : Global.GrpcGunMode,
                };
                break;
        }
        item.SetTransportExtra(transport);
    }

    public static List<ProfileItem>? ResolveFullArray(string strData, string? subRemarks)
    {
        var configObjects = JsonUtils.Deserialize<object[]>(strData);
        if (configObjects is not { Length: > 0 })
        {
            return null;
        }

        List<ProfileItem> lstResult = [];
        foreach (var configObject in configObjects)
        {
            var objectString = JsonUtils.Serialize(configObject);
            var profileIt = ResolveFull(objectString, subRemarks);
            if (profileIt != null)
            {
                lstResult.Add(profileIt);
            }
        }

        return lstResult;
    }

    public static ProfileItem? ResolveFull(string strData, string? subRemarks)
    {
        var config = JsonUtils.ParseJson(strData);
        if (config?["inbounds"] == null
            || config["outbounds"] == null
            || config["routing"] == null)
        {
            return null;
        }

        var fileName = WriteAllText(strData);

        var profileItem = new ProfileItem
        {
            CoreType = ECoreType.Xray,
            Address = fileName,
            Remarks = config?["remarks"]?.ToString() ?? subRemarks ?? "v2ray_custom"
        };

        return profileItem;
    }
}
