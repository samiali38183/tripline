<#
.SYNOPSIS
    Export Sysmon, Security and PowerShell events since a start time as NDJSON in the
    Fluent Bit "winlog" shape tripline's logsource router expects.

.DESCRIPTION
    One JSON object per line: Channel, EventID, TimeCreated (UTC, ISO-8601), ProviderName,
    Computer, RecordNumber, plus every EventData <Data Name="..."> promoted to the top level
    (Image, CommandLine, ParentImage, ScriptBlockText, TaskName, GrantedAccess, ...).

.EXAMPLE
    .\Export-TriplineEvents.ps1 -Since $start -Out events.ndjson
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [datetime] $Since,
    [Parameter(Mandatory)] [string] $Out,
    [int[]] $SecurityIds = @(4688, 4698, 4699, 4702, 4720, 4728),
    [int[]] $PowerShellIds = @(4103, 4104)
)

$ErrorActionPreference = 'Continue'
$filters = @(
    @{ LogName = 'Microsoft-Windows-Sysmon/Operational'; StartTime = $Since },
    @{ LogName = 'Security'; StartTime = $Since; Id = $SecurityIds },
    @{ LogName = 'Microsoft-Windows-PowerShell/Operational'; StartTime = $Since; Id = $PowerShellIds }
)

$utf8 = [System.Text.UTF8Encoding]::new($false)
$writer = [System.IO.StreamWriter]::new($Out, $false, $utf8)
$writer.NewLine = "`n"
$counts = [ordered]@{}
try {
    foreach ($filter in $filters) {
        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -ErrorAction Stop)
        } catch {
            Write-Warning "$($filter.LogName): $($_.Exception.Message)"
            $events = @()
        }
        $n = 0
        foreach ($e in $events) {
            try {
                $xml = [xml]$e.ToXml()
            } catch {
                continue
            }
            $rec = [ordered]@{
                Channel      = $e.LogName
                EventID      = [int]$e.Id
                TimeCreated  = $e.TimeCreated.ToUniversalTime().ToString('o')
                ProviderName = $e.ProviderName
                Computer     = $e.MachineName
                RecordNumber = [long]$e.RecordId
            }
            $data = $xml.Event.EventData.Data
            if ($data) {
                foreach ($d in $data) {
                    if ($d.Name -and -not $rec.Contains($d.Name)) {
                        $rec[$d.Name] = [string]$d.'#text'
                    }
                }
            }
            $writer.WriteLine(($rec | ConvertTo-Json -Compress -Depth 4))
            $n++
        }
        $counts[$filter.LogName] = $n
    }
} finally {
    $writer.Close()
}
$counts | ConvertTo-Json -Compress | Write-Output
