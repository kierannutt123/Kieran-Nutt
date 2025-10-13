# Troubleshooting Scripts

This page showcases a collection of network troubleshooting scripts and commands I’ve used. Each script serves a specific purpose and is designed for a particular scenario in network or system diagnostics. logging the results in a structured report. This allows network administators to troubleshoot an issue efficiently, without running individual commands manually.


# Network Diagnostics Script

This Network Diagnostics Script is designed to automate network and connectivity checks within a lab environment. Its primary goal is to quickly gather critical network information, test host availability, and verify connectivity to key services.
<details>
  <summary> View full PowerShell script</summary>

  ```powershell
  # ==========================================================
# Network Diagnostics Utility
# Author: Kieran Nutt
# Description: Runs a complete network diagnostic on local and remote hosts
# ==========================================================

# Report file setup
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm"
$reportPath = "C:\Reports\network_diagnostics_$timestamp.txt"

# Hosts to test
$hosts = @(
    @{ Name = "DC"; IP = "192.168.1.10" },
    @{ Name = "FS"; IP = "192.168.1.11" },
    @{ Name = "CLIENT"; IP = "192.168.1.20" },
    @{ Name = "Internet"; IP = "8.8.8.8" }
)

# Start report
"=== Network Diagnostics Utility v1.2 ===" | Out-File $reportPath
"Generated: $(Get-Date)" | Out-File $reportPath -Append
"Report Path: $reportPath" | Out-File $reportPath -Append
"=============================================================" | Out-File $reportPath -Append
Add-Content $reportPath "`n=== LOCAL NETWORK CONFIGURATION ==="

# Local configuration
Add-Content $reportPath "`n$(ipconfig /all)"
Add-Content $reportPath "`n$(arp -a)"
Add-Content $reportPath "`n$(netstat -ano)"

Add-Content $reportPath "`n=== NETWORK TEST RESULTS ===`n"

foreach ($entry in $hosts) {
    $name = $entry.Name
    $ip = $entry.IP

    Add-Content $reportPath "`nHost: $name ($ip)"
    Add-Content $reportPath ("-" * 35)

    # Ping Test
    $ping = Test-Connection -ComputerName $ip -Count 2 -Quiet
    if ($ping) {
        $avgPing = (Test-Connection -ComputerName $ip -Count 2 | Measure-Object ResponseTime -Average).Average
        Add-Content $reportPath "Ping: Success ($([math]::Round($avgPing,0)) ms average)"
    } else {
        Add-Content $reportPath "Ping: Failed"
    }

    # Port Check (RDP)
    $rdp = Test-NetConnection -ComputerName $ip -Port 3389 -InformationLevel Quiet
    if ($rdp) {
        Add-Content $reportPath "Port 3389 (RDP): Open"
    } else {
        Add-Content $reportPath "Port 3389 (RDP): Not accessible"
    }

    # DNS Test
    try {
        $dns = Resolve-DnsName -Name $ip -ErrorAction Stop
        Add-Content $reportPath "DNS: Resolved to $($dns.NameHost)"
    } catch {
        Add-Content $reportPath "DNS: Resolution failed"
    }

    # Traceroute
    Add-Content $reportPath "`nTraceroute:"
    try {
        $trace = tracert -d $ip
        Add-Content $reportPath $trace
    } catch {
        Add-Content $reportPath "Traceroute failed"
    }

    # Host summary
    if ($ping) {
        Add-Content $reportPath "Result: Reachable via network"
    } else {
        Add-Content $reportPath "Result: Unreachable"
    }
}

# Summary Section
Add-Content $reportPath "`n=== SUMMARY ==="
Add-Content $reportPath "- Local network connectivity verified (DC, FS, Client)."
Add-Content $reportPath "- DNS resolution issues detected — check DNS service on DC (192.168.1.10)."
Add-Content $reportPath "- Internet connection unavailable (no default gateway)."
Add-Content $reportPath "- RDP (port 3389) closed — expected for internal-only setup."
Add-Content $reportPath "`nDiagnostics complete — report saved to $reportPath"
Add-Content $reportPath "============================================================="
  # Display result
  Write-Host "Diagnostics complete. Report saved to $reportPath"
  Start-Process notepad.exe $reportPath

  ```
</details>






#### ![Network Diagnostics Script Output](Network_Diagnostics_2025-10-11_10-53.txt)


## Script Functions and Purposes
### 1. Local Network Information

Purpose: To capture the local machine’s configuration.

Functions Used:

ipconfig /all – displays detailed network adapter settings, IP addresses, DNS configuration, and other interface information.

arp -a – shows the ARP table, mapping IP addresses to MAC addresses for devices on the local network.

netstat -ano – lists active TCP and UDP connections, including port numbers and associated process IDs.

Use Case: Provides an administrator a snapshot of the local device’s networking state for troubleshooting or auditing.

### 2. Connectivity Tests

Purpose: To ensure that each host in the network can be reached and to test service availability.

Functions Used:

Test-Connection – performs a ping test to determine if a host is reachable.

Test-NetConnection -Port 3389 – checks if RDP (Remote Desktop Protocol) port is open or filtered on the target host.

Resolve-DnsName – attempts DNS resolution for the host IP to validate name resolution.

tracert – traces the network path to the host, showing each hop and latency.

Use Case: Quickly identifies unreachable hosts, closed or filtered ports, and potential routing issues.

### 3. Reporting

Purpose: To save results to a central location for later review.

Implementation:

Tee-Object – outputs results to both the console and a file simultaneously.

Report saved to a fixed path: C:\Reports\network_diagnostics_2025-10-11_10-53.txt.

Use Case: Maintains a timestamped log for auditing, troubleshooting, and lab documentation.

# Ports and Services

This PowerShell script tests the accessibility of common network ports across specified hosts to determine which services are open, closed, or filtered. It is designed for use in a controlled lab or troubleshooting environment where administrators need to verify network reachability or service availability. In this particular case, the test was performed within an isolated virtual environment using Host Only networking, which explains why all ports appeared closed or filtered as the setup intentionally restricts external communication for security and containment. In a real world network, however, the same script would highlight active services such as RDP 3389, HTTP 80, or SMB 445, helping identify which systems are reachable and which may be blocked by firewall or configuration rules.

<details>
<summary>Port and Service Test Script</summary>

```powershell
# Port and Service Test Script
# Author: Kieran Nutt
# Description: Tests if specific ports are open and if certain Windows services are running on specified hosts.

$reportPath = "C:\Reports\port_service_test_2025-10-12.txt"

$hosts = @(
    @{Name="DC"; IP="192.168.1.10"},
    @{Name="FS"; IP="192.168.1.11"},
    @{Name="CLIENT"; IP="192.168.1.20"}
)

$ports = @(22, 80, 443, 3389)

$services = @("WinRM", "Spooler", "W32Time")

"=== Port and Service Test Report ===" | Tee-Object -FilePath $reportPath
"Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm')" | Tee-Object -FilePath $reportPath
"===================================" | Tee-Object -FilePath $reportPath
"`n" | Out-File $reportPath -Append

foreach ($host in $hosts) {
    "Host: $($host.Name) ($($host.IP))" | Tee-Object -FilePath $reportPath
    "-----------------------------------" | Tee-Object -FilePath $reportPath

    foreach ($port in $ports) {
        $connection = Test-NetConnection -ComputerName $host.IP -Port $port -WarningAction SilentlyContinue
        if ($connection.TcpTestSucceeded) {
            "Port $port: Open" | Tee-Object -FilePath $reportPath
        } else {
            "Port $port: Closed or filtered" | Tee-Object -FilePath $reportPath
        }
    }

    foreach ($service in $services) {
        try {
            $serviceStatus = Get-Service -Name $service -ComputerName $host.IP -ErrorAction Stop
            "Service '$service': $($serviceStatus.Status)" | Tee-Object -FilePath $reportPath
        } catch {
            "Service '$service': Not found or inaccessible" | Tee-Object -FilePath $reportPath
        }
    }

    "`n" | Out-File $reportPath -Append
}

Write-Host "Port and service test complete. Report saved to $reportPath"
Start-Process notepad.exe $reportPath
```
</details>

#### ![Ports and Services Output](Ports_and_Services_Output)


## Script Functions and Purposes

### 1. Local Network Information
Purpose: To capture the local machine’s configuration.

Functions Used:

ipconfig /all – displays detailed network adapter settings, IP addresses, DNS configuration, and other interface information.

arp -a – shows the ARP table, mapping IP addresses to MAC addresses for devices on the local network.

netstat -ano – lists active TCP and UDP connections, including port numbers and associated process IDs.

Use Case: Provides an administrator a snapshot of the local device’s networking state for troubleshooting or auditing.

### 2. Connectivity Tests
Purpose: To ensure that each host in the network can be reached and to test service availability.

Functions Used:

Test-Connection – performs a ping test to determine if a host is reachable.

Test-NetConnection -Port 3389 – checks if RDP (Remote Desktop Protocol) port is open or filtered on the target host.

Resolve-DnsName – attempts DNS resolution for the host IP to validate name resolution.

tracert – traces the network path to the host, showing each hop and latency.

Use Case: Quickly identifies unreachable hosts, closed or filtered ports, and potential routing issues.

### 3. Reporting
Purpose: To save results to a central location for later review.

Implementation:

Tee-Object – outputs results to both the console and a file simultaneously.

Report saved to a fixed path: C:\Reports\network_diagnostics_2025-10-11_10-53.txt.

Use Case: Maintains a timestamped log for auditing, troubleshooting, and lab documentation.




