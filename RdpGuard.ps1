function Write-Log($Message) {
    $MyDateTime = Get-Date -Format 'MM-dd-yyyy H:mm:ss'
    $DateForLogFile = Get-Date -Format 'MM-dd-yyyy-Hmmss'
    $LogFilePath = "$LogFilePath-$DateForLogFile.log"
    Add-Content -Path $LogFilePath -Value "$MyDateTime - $Message" -Force
}
	
[string]$LogFilePath = 'C:\Windows\Tasks\Management\RdpGuard'
[string]$BlockedIPsFile = "C:\Windows\Tasks\Management\blocked_ips.txt"
$BlockedIPs = @{}
$MinutesToUnblock = 300 #Minutes to elapsed untill Blocked IP tobe unblocked 300 = 5 Hour
$MinutesToCheckEventsBefore = -5 #Filter and search events that occured Minutes before
$MaxFailedLoginCount = 5 #Max failed login count that after that block IP
$rdpPort = Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" | Select-Object -ExpandProperty PortNumber
# Load previously blocked IPs and their blocked time from the file
$i=1
if (Test-Path $BlockedIPsFile) {
    $BlockedIPsData = Get-Content -Path $BlockedIPsFile
    $BlockedIPsData.split("`n") | ForEach-Object {
        $BlockedIP, $BlockedTime = $_.Split(",")
        $BlockedIPs.Add("$i|$BlockedIP", $BlockedTime)
        $i++
    }
}

$StartTime = (Get-Date).AddMinutes($MinutesToCheckEventsBefore)
$EndTime = Get-Date

$EventLog = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $StartTime
    EndTime   = $EndTime
} -ErrorAction SilentlyContinue

if ($null -ne $EventLog) {
    $FailedIPs = $EventLog | Where-Object {
        $_.Message -match 'Logon Type:\s+3' -and
        $_.Message -match 'Status:\s+0xc000006d'
    } | ForEach-Object {
        $_.Properties[19].Value
    } | Select-Object
    $count = 0
    foreach ($IP in $FailedIPs) {
        # Validate the IP address format
        if ([System.Net.IPAddress]::TryParse($IP, [ref]$null)) {
            foreach ($line in $BlockedIPs.Keys){
                if ($line.Split("|")[1] -match $IP) {
                    $count++
                }
            }
            if ($count -ge 5) {
                # Block the IP using Windows Firewall or any other method you prefer
                # For example, you can use the following command to block the IP using Windows Firewall:
                # Check if a rule already exists to block this IP
                $ruleExists = (Get-NetFirewallRule | Where-Object { $_.DisplayName -eq "Block RDP ($IP)" -and $_.Direction -eq "Inbound"}).Count -gt 0
                if (-not $ruleExists) {
                    netsh advfirewall firewall add rule name="Block RDP ($IP)" dir=in action=block protocol=TCP localport=$rdpPort remoteip=$IP
                    Write-Host "Blocked IP: $IP"
                    Write-Log -Message "- Blocked IP: $IP"
                } else {
                    Write-Host "IP: $IP is already blocked!"
                }
                $NewIPs=@{}
                $i=1
                foreach ($line in $BlockedIPs.Keys){
                    if ($line.Split("|")[1] -notmatch $IP) {
                         $IPBlk=$line.Split("|")[1]
                         $BlockedTime=$BlockedIPs[$line]
                         $NewIPs.Add("$i|$IPBlk", $BlockedTime)
                         $i++
                    }
                }
                $BlockedIPs=$NewIPs
                $i=$BlockedIPs.Count+1
                $BlockedTime = Get-Date
                $BlockedTime = $BlockedTime.ToString("yyyy-MM-dd HH:mm:ss")
                $BlockedIPs.Add("$i|$IP", $BlockedTime)
                # Log the blocked IP to the log file
            } else {
                $i=$BlockedIPs.Count+1
                $BlockedTime = Get-Date
                $BlockedTime = $BlockedTime.ToString("yyyy-MM-dd HH:mm:ss")
                $BlockedIPs.Add("$i|$IP", $BlockedTime)
            }
        }
        else {
            Write-Host "Invalid IP address: $IP"
        }
    }
}
else {
    Write-Host "No events found within the specified time range."
}

# Check if any previously blocked IPs need to be unblocked
$IPsToUnblock = @()
$NewIPs=@{}
$i=1

foreach ($BlockedIP in $BlockedIPs.Keys) {
    $BlockedTime = $BlockedIPs[$BlockedIP]
    $IPBlk=$BlockedIP.Split("|")[1]
    $ElapsedTime = New-TimeSpan -Start $BlockedTime -End (Get-Date)
    if ($ElapsedTime.TotalMinutes -ge $MinutesToUnblock) {
        $IPsToUnblock += $IPBlk
    }else {
        $NewIPs.Add("$i|$IPBlk", $BlockedTime)
        $i++
    }
}
$BlockedIPs=$NewIPs

foreach ($IP in $IPsToUnblock) {
    # Validate the IP address format
    if ([System.Net.IPAddress]::TryParse($IP, [ref]$null)) {
        # Unblock the IP using Windows Firewall or any other method you used for blocking
        # For example, you can use the following command to unblock the IP using Windows Firewall:
        netsh advfirewall firewall delete rule name="Block RDP ($IP)" dir=in remoteip=$IP
        Write-Host "Unblocked IP: $IP"
    
        # Log the unblocked IP to the log file
        Write-Log -Message " - Unblocked IP: $IP"
    }
    else {
        Write-Host "Invalid IP address: $IP"
    }
}

# Save the updated list of blocked IPs and their blocked time to the file
$BlockedIPsData = $BlockedIPs.GetEnumerator() | ForEach-Object { '{0},{1}' -f $_.Key.Split("|")[1], $_.Value }
$BlockedIPsData | Out-File -FilePath $BlockedIPsFile -Force