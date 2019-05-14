<#
  .SYNOPSIS
    This script will query a list of machines (further functionality to be added later) for a list of Applocker Audit-Blocks or Blocks, depending on your applocker policy. 
    The blocked applications are then grouped and sorted by count to aid in modifying your AppLocker policy or investigating suspicious applications.
    Author: Joe McCormack (@bmulley)

  .DESCRIPTION
    This script will connect to each of the listed systems and pull out any event logs that match the given parameters.  The default parameters will be for Applocker blocked executables. 
  .PARAMETER SystemsToCheck
    This parameter can be populated via a comma separated list, or in the future will be an AD query. 
  .PARAMETER Results
    This is populated in each loop with the results from the Get-Winevent AppLocker EXE and DLL events. Can be expanded to be all AppLocker events in the future.
  .PARAMETER Cumulative
    This is the total collected results from all polled systems.

#>


[CmdletBinding()]
 
param (
    $SystemsToCheck = @("<machine name here>")
      )
 
begin {}
 
process {
    rv Cumulative -ErrorAction SilentlyContinue
    rv Results -ErrorAction SilentlyContinue
    rv OutputTable -ErrorAction SilentlyContinue
    
    ForEach ($System in $SystemsToCheck) { 
        rv SystemUsers -ErrorAction SilentlyContinue
        rv ConnectError -ErrorAction SilentlyContinue
        Write-Output "$($System): Connecting..."
        
        If ($ConnectError) {
            Write-Verbose "$($System): Error Connecting" -Verbose
        }
        Else {
               $Results =  Invoke-Command -ComputerName $System -Scriptblock {Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-AppLocker/Exe and DLL";<# StartTime=(get-date).AddDays(-7);#> ID=8003}  }
                    }
                    $Cumulative += $Results
                } 
            echo $Cumulative | Select -Property Message,PSComputerName | Group-Object -Property Message | sort count
            }
            
end {}
