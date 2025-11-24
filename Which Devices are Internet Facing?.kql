// Define a regex that matches *private* and non-routable IP ranges
// Includes: 10.0.0.0/8, 172.16.0.0–172.31.255.255, 192.168.0.0/16,
// loopback (127.*), link-local (169.254.*), and some special ranges (224.*, 240.*)
let PrivateIPRegex = @'^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|169\.254\.|224\.|240\.)';

// How far back to look in the telemetry
let LookbackDays = 30d;

// -------------------------------------------
// 1) Devices with public IPs seen in ConnectedNetworks
// -------------------------------------------
let PublicIPDevices = DeviceNetworkInfo
    // Limit to the lookback window
    | where Timestamp > ago(LookbackDays)
    // Only keep rows where ConnectedNetworks has data
    | where isnotempty(ConnectedNetworks)
    // Expand the ConnectedNetworks JSON array into one row per network object
    | mv-expand ConnectedNetwork = parse_json(ConnectedNetworks)
    // Extract the PublicIP property from each ConnectedNetwork object
    | extend PublicIP = tostring(ConnectedNetwork.PublicIP)
    // Keep only non-empty, non-private IPs (i.e., likely public IPs)
    | where isnotempty(PublicIP) and not(PublicIP matches regex PrivateIPRegex)
    // Aggregate all public IPs per device into a set (distinct list)
    | summarize PublicIPs = make_set(PublicIP) by DeviceId, DeviceName
    // Tag this dataset with how we detected it
    | extend DetectionMethod = "PublicIP";

// -------------------------------------------
// 2) Devices whose *local* IP is actually public
// (e.g., directly assigned public IP address)
// -------------------------------------------
let PublicLocalIP = DeviceNetworkInfo
    // Same lookback window
    | where Timestamp > ago(LookbackDays)
    // Only rows where IPAddresses has data
    | where isnotempty(IPAddresses)
    // Expand IPAddresses JSON array into one row per IP object
    | mv-expand IPAddress = parse_json(IPAddresses)
    // Extract the IPAddress field from each object
    | extend LocalIP = tostring(IPAddress.IPAddress)
    // Keep only non-empty IPs that are not private ranges
    | where isnotempty(LocalIP) and not(LocalIP matches regex PrivateIPRegex)
    // Aggregate all public "local" IPs per device
    | summarize PublicLocalIPs = make_set(LocalIP) by DeviceId, DeviceName
    // Tag how we detected this
    | extend DetectionMethod = "PublicLocalIP";

// -------------------------------------------
// 3) Devices with a significant number of inbound connections
// -------------------------------------------
let InboundConnections = DeviceNetworkEvents
    // Same lookback window
    | where Timestamp > ago(LookbackDays)
    // Only inbound connection accepted events
    | where ActionType == "InboundConnectionAccepted"
    // Exclude private source IPs; keep only external (public-ish) sources
    | where not(RemoteIP matches regex PrivateIPRegex)
    // Extra safety: explicitly exclude some special/broadcast ranges
    | where RemoteIP !in ("169.254.0.0/16", "224.0.0.0/4", "255.255.255.255")
    // Summarize inbound activity per device
    | summarize 
        InboundCount      = count(),                // total accepted inbound connections
        UniqueRemoteIPs   = dcount(RemoteIP),       // number of distinct remote IPs
        RemotePorts       = make_set(RemotePort),   // list of remote ports seen
        SampleRemoteIPs   = make_set(RemoteIP, 5)   // sample up to 5 remote IPs
      by DeviceId, DeviceName
    // Only keep devices with more than 5 inbound connections (tune this threshold)
    | where InboundCount > 5
    // Tag detection method
    | extend DetectionMethod = "InboundConnections";

// -------------------------------------------
// 4) Devices listening on common remote access / service ports
// -------------------------------------------
let RemoteAccessServices = DeviceNetworkEvents
    // Same lookback window
    | where Timestamp > ago(LookbackDays)
    // Focus on common remote access / admin / web ports
    // (22=SSH, 3389=RDP, 443/80=HTTPS/HTTP, 21=FTP, 23=Telnet, 5900=VNC, 5985/5986=WinRM)
    | where RemotePort in (22, 3389, 443, 80, 21, 23, 5900, 5985, 5986)
    // Only inbound accepted events
    | where ActionType == "InboundConnectionAccepted"
    // From non-private IPs (i.e., likely internet-originated)
    | where not(RemoteIP matches regex PrivateIPRegex)
    // Summarize per device: which service ports and how many connections
    | summarize 
        ServicePorts     = make_set(RemotePort),
        ConnectionCount  = count()
      by DeviceId, DeviceName
    // Tag detection method
    | extend DetectionMethod = "RemoteAccessPorts";

// -------------------------------------------
// 5) Devices already flagged as Internet-facing in DeviceInfo
// -------------------------------------------
let IsInternetFacingDevices = DeviceInfo
    // Same lookback window
    | where Timestamp > ago(LookbackDays)
    // Only devices explicitly flagged as Internet-facing
    | where IsInternetFacing == true
    // Distinct list per DeviceId/DeviceName
    | distinct DeviceId, DeviceName
    // Tag detection method
    | extend DetectionMethod = "IsInternetFacing";

// -------------------------------------------
// 6) Union all detections, merge by DeviceId/DeviceName
// -------------------------------------------

// Start with devices that had public IPs from ConnectedNetworks
PublicIPDevices
// Full outer join with devices that had public LocalIP
| join kind=fullouter (PublicLocalIP) on DeviceId, DeviceName
// Full outer join with devices that had inbound connections
| join kind=fullouter (InboundConnections) on DeviceId, DeviceName
// Full outer join with devices on remote access/service ports
| join kind=fullouter (RemoteAccessServices) on DeviceId, DeviceName
// Full outer join with devices explicitly marked as Internet-facing
| join kind=fullouter (IsInternetFacingDevices) on DeviceId, DeviceName

// After multiple joins, the same logical field may exist as DeviceId, DeviceId1, DeviceId2...
// coalesce() picks the first non-null value across those
| extend DeviceId   = coalesce(DeviceId,   DeviceId1,   DeviceId2,   DeviceId3,   DeviceId4)
| extend DeviceName = coalesce(DeviceName, DeviceName1, DeviceName2, DeviceName3, DeviceName4)

// Combine all public IP lists (from ConnectedNetworks or LocalIP)
| extend AllPublicIPs = coalesce(PublicIPs, PublicLocalIPs)

// Combine all detection method tags into one comma-separated string
| extend DetectionMethods = strcat_array(
                                pack_array(
                                    DetectionMethod, DetectionMethod1, 
                                    DetectionMethod2, DetectionMethod3, DetectionMethod4
                                ), 
                                ", "
                            )

// Ensure these complex fields are converted to string for output
| extend RemotePortsStr  = tostring(RemotePorts)
| extend ServicePortsStr = tostring(ServicePorts)
| extend PublicIPList    = tostring(AllPublicIPs)

// Choose the final set of columns to output
| project 
    DeviceId, 
    DeviceName, 
    PublicIPList, 
    DetectionMethods, 
    InboundCount, 
    UniqueRemoteIPs, 
    RemotePortsStr, 
    ServicePortsStr

// If there are multiple rows per device, pick the row with the "highest" DetectionMethods value
// (arg_max uses the lexicographically max DetectionMethods as the tiebreaker)
| summarize arg_max(DetectionMethods, *) by DeviceId, DeviceName
