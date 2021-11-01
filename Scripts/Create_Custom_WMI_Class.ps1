<#
.SYNOPSIS
    Update GeoLocation Data
.DESCRIPTION
    Update GeoLocation Data
.NOTES
    Fichier    : Update_GeoLocation_Data.ps1
    Author     : Jerome Couette - j.couette@cpu.ca
    Version    : 1.0
#>

#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function Write-Log {
    <#
    .SYNOPSIS
        Write messages to a log file in CMTrace.exe compatible format or Legacy text file format.
    .DESCRIPTION
        Write messages to a log file in CMTrace.exe compatible format or Legacy text file format and optionally display in the console.
    .PARAMETER Message
        The message to write to the log file or output to the console.
    .PARAMETER Severity
        Defines message type. When writing to console or CMTrace.exe log format, it allows highlighting of message type.
        Options: 1 = Information (default), 2 = Warning (highlighted in yellow), 3 = Error (highlighted in red)
    .PARAMETER Source
        The source of the message being logged.
    .PARAMETER ScriptSection
        The heading for the portion of the script that is being executed. Default is: $script:installPhase.
    .PARAMETER LogType
        Choose whether to write a CMTrace.exe compatible log file or a Legacy text log file.
    .PARAMETER LogFileDirectory
        Set the directory where the log file will be saved.
        Default is %WINDIR%\Logs\WmiToolkit.
    .PARAMETER LogFileName
        Set the name of the log file.
    .PARAMETER MaxLogFileSizeMB
        Maximum file size limit for log file in megabytes (MB). Default is 10 MB.
    .PARAMETER WriteHost
        Write the log message to the console.
    .PARAMETER ContinueOnError
        Suppress writing log message to console on failure to write message to log file. Default is: $true.
    .PARAMETER PassThru
        Return the message that was passed to the function
    .PARAMETER DebugMessage
        Specifies that the message is a debug message. Debug messages only get logged if -LogDebugMessage is set to $true.
    .PARAMETER LogDebugMessage
        Debug messages only get logged if this parameter is set to $true in the config XML file.
    .EXAMPLE
        Write-Log -Message "Installing patch MS15-031" -Source 'Add-Patch' -LogType 'CMTrace'
    .EXAMPLE
        Write-Log -Message "Script is running on Windows 8" -Source 'Test-ValidOS' -LogType 'Legacy'
    .NOTES
    .LINK
        https://psappdeploytoolkit.com
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
            [AllowEmptyCollection()]
            [Alias('Text')]
            [string[]]$Message,
            [Parameter(Mandatory=$false,Position=1)]
            [ValidateRange(1,3)]
            [int16]$Severity = 1,
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNull()]
            [string]$Source = '',
            [Parameter(Mandatory=$false,Position=3)]
            [ValidateNotNullorEmpty()]
            [string]$ScriptSection = 'Module',
            [Parameter(Mandatory=$false,Position=4)]
            [ValidateSet('CMTrace','Legacy')]
            [string]$LogType = 'Legacy',
            [Parameter(Mandatory=$false,Position=5)]
            [ValidateNotNullorEmpty()]
            [string]$LogFileDirectory = $(Join-Path -Path $Env:windir -ChildPath '\Logs\PSWmiToolKit'),
            [Parameter(Mandatory=$false,Position=6)]
            [ValidateNotNullorEmpty()]
            [string]$LogFileName = 'PSWmiToolKit.log',
            [Parameter(Mandatory=$false,Position=7)]
            [ValidateNotNullorEmpty()]
            [decimal]$MaxLogFileSizeMB = '5',
            [Parameter(Mandatory=$false,Position=8)]
            [ValidateNotNullorEmpty()]
            [boolean]$WriteHost = $true,
            [Parameter(Mandatory=$false,Position=9)]
            [ValidateNotNullorEmpty()]
            [boolean]$ContinueOnError = $true,
            [Parameter(Mandatory=$false,Position=10)]
            [switch]$PassThru = $false,
            [Parameter(Mandatory=$false,Position=11)]
            [switch]$DebugMessage = $false,
            [Parameter(Mandatory=$false,Position=12)]
            [boolean]$LogDebugMessage = $false
        )
    
        Begin {
            ## Get the name of this function
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
    
            ## Logging Variables
            #  Log file date/time
            [string]$LogTime = (Get-Date -Format 'HH:mm:ss.fff').ToString()
            [string]$LogDate = (Get-Date -Format 'MM-dd-yyyy').ToString()
            If (-not (Test-Path -LiteralPath 'variable:LogTimeZoneBias')) { [int32]$script:LogTimeZoneBias = [timezone]::CurrentTimeZone.GetUtcOffset([datetime]::Now).TotalMinutes }
            [string]$LogTimePlusBias = $LogTime + $script:LogTimeZoneBias
            #  Initialize variables
            [boolean]$ExitLoggingFunction = $false
            If (-not (Test-Path -LiteralPath 'variable:DisableLogging')) { $DisableLogging = $false }
            #  Check if the script section is defined
            [boolean]$ScriptSectionDefined = [boolean](-not [string]::IsNullOrEmpty($ScriptSection))
            #  Get the file name of the source script
            Try {
                If ($script:MyInvocation.Value.ScriptName) {
                    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.Value.ScriptName -Leaf -ErrorAction 'Stop'
                }
                Else {
                    [string]$ScriptSource = Split-Path -Path $script:MyInvocation.MyCommand.Definition -Leaf -ErrorAction 'Stop'
                }
            }
            Catch {
                $ScriptSource = ''
            }
    
            ## Create script block for generating CMTrace.exe compatible log entry
            [scriptblock]$CMTraceLogString = {
                Param (
                    [string]$lMessage,
                    [string]$lSource,
                    [int16]$lSeverity
                )
                "<![LOG[$lMessage]LOG]!>" + "<time=`"$LogTimePlusBias`" " + "date=`"$LogDate`" " + "component=`"$lSource`" " + "context=`"$([Security.Principal.WindowsIdentity]::GetCurrent().Name)`" " + "type=`"$lSeverity`" " + "thread=`"$PID`" " + "file=`"$ScriptSource`">"
            }
    
            ## Create script block for writing log entry to the console
            [scriptblock]$WriteLogLineToHost = {
                Param (
                    [string]$lTextLogLine,
                    [int16]$lSeverity
                )
                If ($WriteHost) {
                    #  Only output using color options if running in a host which supports colors.
                    If ($Host.UI.RawUI.ForegroundColor) {
                        Switch ($lSeverity) {
                            3 { Write-Host -Object $lTextLogLine -ForegroundColor 'Red' -BackgroundColor 'Black' }
                            2 { Write-Host -Object $lTextLogLine -ForegroundColor 'Yellow' -BackgroundColor 'Black' }
                            1 { Write-Host -Object $lTextLogLine }
                        }
                    }
                    #  If executing "powershell.exe -File <filename>.ps1 > log.txt", then all the Write-Host calls are converted to Write-Output calls so that they are included in the text log.
                    Else {
                        Write-Output -InputObject $lTextLogLine
                    }
                }
            }
    
            ## Exit function if it is a debug message and logging debug messages is not enabled in the config XML file
            If (($DebugMessage) -and (-not $LogDebugMessage)) { [boolean]$ExitLoggingFunction = $true; Return }
            ## Exit function if logging to file is disabled and logging to console host is disabled
            If (($DisableLogging) -and (-not $WriteHost)) { [boolean]$ExitLoggingFunction = $true; Return }
            ## Exit Begin block if logging is disabled
            If ($DisableLogging) { Return }
            ## Exit function function if it is an [Initialization] message and the toolkit has been relaunched
        If ($ScriptSection -eq 'Initialization') { [boolean]$ExitLoggingFunction = $true; Return }
    
            ## Create the directory where the log file will be saved
            If (-not (Test-Path -LiteralPath $LogFileDirectory -PathType 'Container')) {
                Try {
                    $null = New-Item -Path $LogFileDirectory -Type 'Directory' -Force -ErrorAction 'Stop'
                }
                Catch {
                    [boolean]$ExitLoggingFunction = $true
                    #  If error creating directory, write message to console
                    If (-not $ContinueOnError) {
                        Write-Host -Object "[$LogDate $LogTime] [${CmdletName}] $ScriptSection :: Failed to create the log directory [$LogFileDirectory]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                    }
                    Return
                }
            }
    
            ## Assemble the fully qualified path to the log file
            [string]$LogFilePath = Join-Path -Path $LogFileDirectory -ChildPath $LogFileName
        }
        Process {
            ## Exit function if logging is disabled
            If ($ExitLoggingFunction) { Return }
    
            ForEach ($Msg in $Message) {
                ## If the message is not $null or empty, create the log entry for the different logging methods
                [string]$CMTraceMsg = ''
                [string]$ConsoleLogLine = ''
                [string]$LegacyTextLogLine = ''
                If ($Msg) {
                    #  Create the CMTrace log message
                    If ($ScriptSectionDefined) { [string]$CMTraceMsg = "[$ScriptSection] :: $Msg" }
    
                    #  Create a Console and Legacy "text" log entry
                    [string]$LegacyMsg = "[$LogDate $LogTime]"
                    If ($ScriptSectionDefined) { [string]$LegacyMsg += " [$ScriptSection]" }
                    If ($Source) {
                        [string]$ConsoleLogLine = "$LegacyMsg [$Source] :: $Msg"
                        Switch ($Severity) {
                            3 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Error] :: $Msg" }
                            2 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Warning] :: $Msg" }
                            1 { [string]$LegacyTextLogLine = "$LegacyMsg [$Source] [Info] :: $Msg" }
                        }
                    }
                    Else {
                        [string]$ConsoleLogLine = "$LegacyMsg :: $Msg"
                        Switch ($Severity) {
                            3 { [string]$LegacyTextLogLine = "$LegacyMsg [Error] :: $Msg" }
                            2 { [string]$LegacyTextLogLine = "$LegacyMsg [Warning] :: $Msg" }
                            1 { [string]$LegacyTextLogLine = "$LegacyMsg [Info] :: $Msg" }
                        }
                    }
                }
    
                ## Execute script block to create the CMTrace.exe compatible log entry
                [string]$CMTraceLogLine = & $CMTraceLogString -lMessage $CMTraceMsg -lSource $Source -lSeverity $Severity
    
                ## Choose which log type to write to file
                If ($LogType -ieq 'CMTrace') {
                    [string]$LogLine = $CMTraceLogLine
                }
                Else {
                    [string]$LogLine = $LegacyTextLogLine
                }
    
                ## Write the log entry to the log file if logging is not currently disabled
                If (-not $DisableLogging) {
                    Try {
                        $LogLine | Out-File -FilePath $LogFilePath -Append -NoClobber -Force -Encoding 'UTF8' -ErrorAction 'Stop'
                    }
                    Catch {
                        If (-not $ContinueOnError) {
                            Write-Host -Object "[$LogDate $LogTime] [$ScriptSection] [${CmdletName}] :: Failed to write message [$Msg] to the log file [$LogFilePath]. `n$(Resolve-Error)" -ForegroundColor 'Red'
                        }
                    }
                }
    
                ## Execute script block to write the log entry to the console if $WriteHost is $true
                & $WriteLogLineToHost -lTextLogLine $ConsoleLogLine -lSeverity $Severity
            }
        }
        End {
            ## Archive log file if size is greater than $MaxLogFileSizeMB and $MaxLogFileSizeMB > 0
            Try {
                If ((-not $ExitLoggingFunction) -and (-not $DisableLogging)) {
                    [IO.FileInfo]$LogFile = Get-ChildItem -LiteralPath $LogFilePath -ErrorAction 'Stop'
                    [decimal]$LogFileSizeMB = $LogFile.Length/1MB
                    If (($LogFileSizeMB -gt $MaxLogFileSizeMB) -and ($MaxLogFileSizeMB -gt 0)) {
                        ## Change the file extension to "lo_"
                        [string]$ArchivedOutLogFile = [IO.Path]::ChangeExtension($LogFilePath, 'lo_')
                        [hashtable]$ArchiveLogParams = @{ ScriptSection = $ScriptSection; Source = ${CmdletName}; Severity = 2; LogFileDirectory = $LogFileDirectory; LogFileName = $LogFileName; LogType = $LogType; MaxLogFileSizeMB = 0; WriteHost = $WriteHost; ContinueOnError = $ContinueOnError; PassThru = $false }
    
                        ## Log message about archiving the log file
                        $ArchiveLogMessage = "Maximum log file size [$MaxLogFileSizeMB MB] reached. Rename log file to [$ArchivedOutLogFile]."
                        Write-Log -Message $ArchiveLogMessage @ArchiveLogParams
    
                        ## Archive existing log file from <filename>.log to <filename>.lo_. Overwrites any existing <filename>.lo_ file. This is the same method SCCM uses for log files.
                        Move-Item -LiteralPath $LogFilePath -Destination $ArchivedOutLogFile -Force -ErrorAction 'Stop'
    
                        ## Start new log file and Log message about archiving the old log file
                        $NewLogMessage = "Previous log file was renamed to [$ArchivedOutLogFile] because maximum log file size of [$MaxLogFileSizeMB MB] was reached."
                        Write-Log -Message $NewLogMessage @ArchiveLogParams
                    }
                }
            }
            Catch {
                ## If renaming of file fails, script will continue writing to log file even if size goes over the max file size
            }
            Finally {
                If ($PassThru) { Write-Output -InputObject $Message }
            }
        }
}

Function Write-FunctionHeaderOrFooter {
    <#
    .SYNOPSIS
        Write the function header or footer to the log upon first entering or exiting a function.
    .DESCRIPTION
        Write the "Function Start" message, the bound parameters the function was invoked with, or the "Function End" message when entering or exiting a function.
        Messages are debug messages so will only be logged if LogDebugMessage option is enabled in XML config file.
    .PARAMETER CmdletName
        The name of the function this function is invoked from.
    .PARAMETER CmdletBoundParameters
        The bound parameters of the function this function is invoked from.
    .PARAMETER Header
        Write the function header.
    .PARAMETER Footer
        Write the function footer.
    .EXAMPLE
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    .EXAMPLE
        Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
    .NOTES
        This is an internal script function and should typically not be called directly.
    .LINK
        https://psappdeploytoolkit.com
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true)]
            [ValidateNotNullorEmpty()]
            [string]$CmdletName,
            [Parameter(Mandatory=$true,ParameterSetName='Header')]
            [AllowEmptyCollection()]
            [hashtable]$CmdletBoundParameters,
            [Parameter(Mandatory=$true,ParameterSetName='Header')]
            [switch]$Header,
            [Parameter(Mandatory=$true,ParameterSetName='Footer')]
            [switch]$Footer
        )
    
        If ($Header) {
            Write-Log -Message 'Function Start' -Source ${CmdletName} -DebugMessage
    
            ## Get the parameters that the calling function was invoked with
            [string]$CmdletBoundParameters = $CmdletBoundParameters | Format-Table -Property @{ Label = 'Parameter'; Expression = { "[-$($_.Key)]" } }, @{ Label = 'Value'; Expression = { $_.Value }; Alignment = 'Left' } -AutoSize -Wrap | Out-String
            If ($CmdletBoundParameters) {
                Write-Log -Message "Function invoked with bound parameter(s): `n$CmdletBoundParameters" -Source ${CmdletName} -DebugMessage
            }
            Else {
                Write-Log -Message 'Function invoked without any bound parameters.' -Source ${CmdletName} -DebugMessage
            }
        }
        ElseIf ($Footer) {
            Write-Log -Message 'Function End' -Source ${CmdletName} -DebugMessage
        }
}
Function Set-WmiClassQualifier {
    <#
    .SYNOPSIS
        This function is used to set qualifiers to a WMI class.
    .DESCRIPTION
        This function is used to set qualifiers to a WMI class. Existing qualifiers with the same name will be overwriten
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI namespace. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name for which to add the qualifiers.
    .PARAMETER Qualifier
        Specifies the qualifier name, value and flavours as hashtable. You can omit this parameter or enter one or more items in the hashtable.
        You can also specify a string but you must separate the name and value with a new line character (`n). This parameter can also be piped.
        If you omit a hashtable item the default item value will be used. Only item values can be specified (right of the '=' sign).
        Default is:
            [hashtable][ordered]@{
                Name = 'Static'
                Value = $true
                IsAmended = $false
                PropagatesToInstance = $true
                PropagatesToSubClass = $false
                IsOverridable = $true
            }
    .EXAMPLE
        Set-WmiClassQualifier -Namespace 'ROOT' -ClassName 'SCCMZone' -Qualifier @{ Name = 'Description'; Value = 'SCCMZone Blog' }
    .EXAMPLE
        Set-WmiClassQualifier -Namespace 'ROOT' -ClassName 'SCCMZone' -Qualifier "Name = Description `n Value = SCCMZone Blog"
    .EXAMPLE
        "Name = Description `n Value = SCCMZone Blog" | Set-WmiClassQualifier -Namespace 'ROOT' -ClassName 'SCCMZone'
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$false,Position=0)]
        [ValidateNotNullorEmpty()]
        [string]$Namespace = 'ROOT\cimv2',
        [Parameter(Mandatory=$true,Position=1)]
        [ValidateNotNullorEmpty()]
        [string]$ClassName,
        [Parameter(Mandatory=$false,ValueFromPipeline,Position=2)]
        [ValidateNotNullorEmpty()]
        [PSCustomObject]$Qualifier = @()
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the class exist
                $null = Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'Stop'
    
                ## If input qualifier is not a hashtable convert string input to hashtable
                If ($Qualifier -isnot [hashtable]) {
                    $Qualifier = $Qualifier | ConvertFrom-StringData
                }
    
                ## Add the missing qualifier value, name and flavor to the hashtable using splatting
                If (-not $Qualifier.Item('Name')) { $Qualifier.Add('Name', 'Static') }
                If (-not $Qualifier.Item('Value')) { $Qualifier.Add('Value', $true) }
                If (-not $Qualifier.Item('IsAmended')) { $Qualifier.Add('IsAmended', $false) }
                If (-not $Qualifier.Item('PropagatesToInstance')) { $Qualifier.Add('PropagatesToInstance', $true) }
                If (-not $Qualifier.Item('PropagatesToSubClass')) { $Qualifier.Add('PropagatesToSubClass', $false) }
                If (-not $Qualifier.Item('IsOverridable')) { $Qualifier.Add('IsOverridable', $true) }
    
                ## Create the ManagementClass object
                [wmiclass]$ClassObject = New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList @("\\.\$Namespace`:$ClassName")
    
                ## Set key qualifier if specified, otherwise set qualifier
                $ClassObject.Qualifiers.Add($Qualifier.Item('Name'), $Qualifier.Item('Value'), $Qualifier.Item('IsAmended'), $Qualifier.Item('PropagatesToInstance'), $Qualifier.Item('PropagatesToSubClass'), $Qualifier.Item('IsOverridable'))
                $SetClassQualifiers = $ClassObject.Put()
                $ClassObject.Dispose()
    
                ## On class qualifiers creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $SetClassQualifiers) {
    
                    #  Error handling and logging
                    $SetClassQualifiersErr = "Failed to set qualifier [$Qualifier.Item('Name')] for class [$Namespace`:$ClassName]."
                    Write-Log -Message $SetClassQualifiersErr -Severity 3 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $SetClassQualifiersErr -Category 'InvalidResult'
                }
            }
            Catch {
                Write-Log -Message "Failed to set qualifier for class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $SetClassQualifiers
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function Set-WmiPropertyQualifier {
    <#
    .SYNOPSIS
        This function is used to set WMI property qualifier value.
    .DESCRIPTION
        This function is used to set WMI property qualifier value to an existing WMI property.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI namespace. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name for which to add the properties.
    .PARAMETER PropertyName
        Specifies the property name.
    .PARAMETER Qualifier
        Specifies the qualifier name, value and flavours as hashtable. You can omit this parameter or enter one or more items in the hashtable.
        You can also specify a string but you must separate the name and value with a new line character (`n). This parameter can also be piped.
        If you omit a hashtable item the default item value will be used. Only item values can be specified (right of the '=' sign).
        Default is:
            [hashtable][ordered]@{
                Name = 'Static'
                Value = $true
                IsAmended = $false
                PropagatesToInstance = $true
                PropagatesToSubClass = $false
                IsOverridable = $true
            }
        Specifies if the property is key. Default is: $false.
    .EXAMPLE
        Set-WmiPropertyQualifier -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -Property 'WebSite' -Qualifier @{ Name = 'Description' ; Value = 'SCCMZone Blog' }
    .EXAMPLE
        Set-WmiPropertyQualifier -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -Property 'WebSite' -Qualifier "Name = Description `n Value = SCCMZone Blog"
    .EXAMPLE
        "Name = Description `n Value = SCCMZone Blog" | Set-WmiPropertyQualifier -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -Property 'WebSite'
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName,
            [Parameter(Mandatory=$true,Position=2)]
            [ValidateNotNullorEmpty()]
            [string]$PropertyName,
            [Parameter(Mandatory=$false,ValueFromPipeline,Position=3)]
            [ValidateNotNullorEmpty()]
            [PSCustomObject]$Qualifier = @()
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the property exists
                $null = Get-WmiProperty -Namespace $Namespace -ClassName $ClassName -PropertyName $PropertyName -ErrorAction 'Stop'
    
                ## If input qualifier is not a hashtable convert string input to hashtable
                If ($Qualifier -isnot [hashtable]) {
                    $Qualifier = $Qualifier | ConvertFrom-StringData
                }
    
                ## Add the missing qualifier value, name and flavor to the hashtable using splatting
                If (-not $Qualifier.Item('Name')) { $Qualifier.Add('Name', 'Static') }
                If (-not $Qualifier.Item('Value')) { $Qualifier.Add('Value', $true) }
                If (-not $Qualifier.Item('IsAmended')) { $Qualifier.Add('IsAmended', $false) }
                If (-not $Qualifier.Item('PropagatesToInstance')) { $Qualifier.Add('PropagatesToInstance', $true) }
                If (-not $Qualifier.Item('PropagatesToSubClass')) { $Qualifier.Add('PropagatesToSubClass', $false) }
                If (-not $Qualifier.Item('IsOverridable')) { $Qualifier.Add('IsOverridable', $true) }
    
                ## Create the ManagementClass object
                [wmiclass]$ClassObject = New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList @("\\.\$Namespace`:$ClassName")
    
                ## Set key qualifier if specified, otherwise set qualifier
                If ('key' -eq $Qualifier.Item('Name')) {
                    $ClassObject.Properties[$PropertyName].Qualifiers.Add('Key', $true)
                    $SetClassQualifiers = $ClassObject.Put()
                    $ClassObject.Dispose()
                }
                Else {
                    $ClassObject.Properties[$PropertyName].Qualifiers.Add($Qualifier.Item('Name'), $Qualifier.Item('Value'), $Qualifier.Item('IsAmended'), $Qualifier.Item('PropagatesToInstance'), $Qualifier.Item('PropagatesToSubClass'), $Qualifier.Item('IsOverridable'))
                    $SetClassQualifiers = $ClassObject.Put()
                    $ClassObject.Dispose()
                }
    
                ## On property qualifiers creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $SetClassQualifiers) {
    
                    #  Error handling and logging
                    $SetClassQualifiersErr = "Failed to set qualifier [$Qualifier.Item('Name')] for property [$Namespace`:$ClassName($PropertyName)]."
                    Write-Log -Message $SetClassQualifiersErr -Severity 3 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $SetClassQualifiersErr -Category 'InvalidResult'
                }
            }
            Catch {
                Write-Log -Message "Failed to set property qualifier for class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
            }
            Finally {
                Write-Output -InputObject $SetClassQualifiers
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function Get-WmiNamespace {
    <#
    .SYNOPSIS
        This function is used to get WMI namespace information.
    .DESCRIPTION
        This function is used to get the details of one or more WMI namespaces.
    .PARAMETER Namespace
        Specifies the namespace(s) path(s). Supports wildcards only when not using the -Recurse or -List switch. Can be piped.
    .PARAMETER List
        This switch is used to list all namespaces in the specified path. Cannot be used in conjunction with the -Recurse switch.
    .PARAMETER Recurse
        This switch is used to get the whole WMI namespace tree recursively. Cannot be used in conjunction with the -List switch.
    .EXAMPLE
        C:\PS> Get-WmiNamespace -NameSpace 'ROOT\SCCM'
    .EXAMPLE
        C:\PS> Get-WmiNamespace -NameSpace 'ROOT\*CM'
    .EXAMPLE
        C:\PS> Get-WmiNamespace -NameSpace 'ROOT' -List
    .EXAMPLE
        C:\PS> Get-WmiNamespace -NameSpace 'ROOT' -Recurse
    .EXAMPLE
        C:\PS> 'Root\SCCM', 'Root\SC*' | Get-WmiNamespace
    .INPUTS
        System.String[].
    .OUTPUTS
        System.Management.Automation.PSCustomObject.
            'Name'
            'Path'
            'FullName'
    .NOTES
        This is a public module function and can typically be called directly.
    .LINK
        https://github.com/JhonnyTerminus/PSWmiToolKit
    .LINK
        https://sccm-zone.com
    .COMPONENT
        WMI
    .FUNCTIONALITY
        WMI Management
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,ValueFromPipeline,Position=0)]
            [ValidateNotNullorEmpty()]
            [SupportsWildcards()]
            [string[]]$Namespace,
            [Parameter(Mandatory=$false,Position=1)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({
                If ($Namespace -match '\*') { Throw 'Wildcards are not supported with this switch.' }
                Return $true
            })]
            [switch]$List = $false,
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNullorEmpty()]
            [ValidateScript({
                If ($Namespace -match '\*') { Throw 'Wildcards are not supported with this switch.' }
                Return $true
            })]
            [switch]$Recurse = $false
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
    
            ## Initialize result variable
            [PSCustomObject]$GetNamespace = $null
        }
        Process {
            Try {
    
                ## Get namespace tree recursively if specified, otherwise just get the current namespace
                If ($Recurse) {
    
                    #  Call Get-WmiNamespaceRecursive internal function
                    $GetNamespace = Get-WmiNamespaceRecursive -Namespace $Namespace -ErrorAction 'SilentlyContinue' | Sort-Object -Property Path
                }
                Else {
    
                    ## If namespace is 'ROOT' or -List is specified get namespace else get Parent\Leaf namespace
                    If ($List -or ($Namespace -eq 'ROOT')) {
                        $WmiNamespace = Get-CimInstance -Namespace $([string]$Namespace) -ClassName '__Namespace' -ErrorAction 'SilentlyContinue' -ErrorVariable Err
                    }
                    Else {
                        #  Set namespace path and name
                        [string]$NamespaceParent = $(Split-Path -Path $Namespace -Parent)
                        [string]$NamespaceLeaf = $(Split-Path -Path $Namespace -Leaf)
                        #  Get namespace
                        $WmiNamespace = Get-CimInstance -Namespace $NamespaceParent -ClassName '__Namespace' -ErrorAction 'SilentlyContinue' -ErrorVariable Err | Where-Object { $_.Name -like $NamespaceLeaf }
                    }
    
                    ## If no namespace is found, write debug message and optionally throw error is -ErrorAction 'Stop' is specified
                    If (-not $WmiNamespace -and $List -and (-not $Err)) {
                        $NamespaceChildrenNotFoundErr = "Namespace [$Namespace] has no children."
                        Write-Log -Message $NamespaceChildrenNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                        Write-Error -Message $NamespaceChildrenNotFoundErr -Category 'ObjectNotFound'
                    }
                    ElseIf (-not $WmiNamespace) {
                        $NamespaceNotFoundErr = "Namespace [$Namespace] not found."
                        Write-Log -Message $NamespaceNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                        Write-Error -Message $NamespaceNotFoundErr -Category 'ObjectNotFound'
                    }
                    ElseIf (-not $Err) {
                        $GetNamespace = $WmiNamespace | ForEach-Object {
                            [PSCustomObject]@{
                                Name = $Name = $_.Name
                                #  Standardize namespace path separator by changing it from '/' to '\'.
                                Path = $Path = $_.CimSystemProperties.Namespace -replace ('/','\')
                                FullName = "$Path`\$Name"
                            }
                        }
                    }
                }
            }
            Catch {
                Write-Log -Message "Failed to retrieve wmi namespace [$Namespace]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
    
                ## If we have anyting to return, add typename for formatting purposes, otherwise set the result to $null
                If ($GetNamespace) {
                    $GetNamespace.PSObject.TypeNames.Insert(0,'Get.WmiNamespace.Typename')
                }
                Else {
                    $GetNamespace = $null
                }
    
                ## Return result
                Write-Output -InputObject $GetNamespace
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }

}
Function Get-WmiClass {
    <#
    .SYNOPSIS
        This function is used to get WMI class details.
    .DESCRIPTION
        This function is used to get the details of one or more WMI classes.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI class. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name to search for. Supports wildcards. Default is: '*'.
    .PARAMETER QualifierName
        Specifies the qualifier name to search for.(Optional)
    .PARAMETER IncludeSpecialClasses
        Specifies to include System, MSFT and CIM classes. Use this or Get operations only.
    .EXAMPLE
        Get-WmiClass -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone'
    .EXAMPLE
        Get-WmiClass -Namespace 'ROOT\SCCM' -QualifierName 'Description'
    .EXAMPLE
        Get-WmiClass -Namespace 'ROOT\SCCM'
    .INPUTS
        None.
    .OUTPUTS
        None.
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    .COMPONENT
        WMI
    .FUNCTIONALITY
        WMI Management
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$false,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName = '*',
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNullorEmpty()]
            [string]$QualifierName,
            [Parameter(Mandatory=$false,Position=3)]
            [ValidateNotNullorEmpty()]
            [switch]$IncludeSpecialClasses
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the namespace exists
                $NamespaceTest = Get-WmiNamespace -Namespace $Namespace -ErrorAction 'SilentlyContinue'
                If (-not $NamespaceTest) {
                    $NamespaceNotFoundErr = "Namespace [$Namespace] not found."
                    Write-Log -Message $NamespaceNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $NamespaceNotFoundErr -Category 'ObjectNotFound'
                }
    
                ## Get all class details
                If ($QualifierName) {
                    $WmiClass = Get-CimClass -Namespace $Namespace -Class $ClassName -QualifierName $QualifierName -ErrorAction 'SilentlyContinue'
                }
                Else {
                    $WmiClass = Get-CimClass -Namespace $Namespace -Class $ClassName -ErrorAction 'SilentlyContinue'
                }
    
                ## Filter class or classes details based on specified parameters
                If ($IncludeSpecialClasses) {
                    $GetClass = $WmiClass
                }
                Else {
                    $GetClass = $WmiClass | Where-Object { ($_.CimClassName -notmatch '__') -and ($_.CimClassName -notmatch 'CIM_') -and ($_.CimClassName -notmatch 'MSFT_') }
                }
    
                ## If no class is found, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $GetClass) {
                    $ClassNotFoundErr = "No class [$ClassName] found in namespace [$Namespace]."
                    Write-Log -Message $ClassNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $ClassNotFoundErr -Category 'ObjectNotFound'
                }
            }
            Catch {
                Write-Log -Message "Failed to retrieve wmi class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
    
                ## If we have anyting to return, add typename for formatting purposes, otherwise set the result to $null
                If ($GetClass) {
                    $GetClass.PSObject.TypeNames.Insert(0,'Get.WmiClass.Typename')
                }
                Else {
                    $GetClass = $null
                }
    
                ## Return result
                Write-Output -InputObject $GetClass
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}

Function Get-WmiProperty {
    <#
    .SYNOPSIS
        This function is used to get the properties of a WMI class.
    .DESCRIPTION
        This function is used to get one or more properties of a WMI class.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI class. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name for which to get the properties.
    .PARAMETER PropertyName
        Specifies the propery name to search for. Supports wildcards. Default is: '*'.
    .PARAMETER PropertyValue
        Specifies the propery value or values to search for. Supports wildcards.(Optional)
    .PARAMETER QualifierName
        Specifies the property qualifier name to match. Supports wildcards.(Optional)
    .PARAMETER Property
        Matches property Name, Value and CimType. Can be piped. If this parameter is specified all other search parameters will be ignored.(Optional)
        Supported format:
            [PSCustomobject]@{
                'Name' = 'Website'
                'Value' = $null
                'CimType' = 'String'
            }
    .EXAMPLE
        Get-WmiProperty -Namespace 'ROOT' -ClassName 'SCCMZone'
    .EXAMPLE
        Get-WmiProperty -Namespace 'ROOT' -ClassName 'SCCMZone' -PropertyName 'WebsiteSite' -QualifierName 'key'
    .EXAMPLE
        Get-WmiProperty -Namespace 'ROOT' -ClassName 'SCCMZone' -PropertyName '*Site'
    .EXAMPLE
        $Property = [PSCustomobject]@{
            'Name' = 'Website'
            'Value' = $null
            'CimType' = 'String'
        }
        Get-WmiProperty -Namespace 'ROOT' -ClassName 'SCCMZone' -Property $Property
        $Property | Get-WmiProperty -Namespace 'ROOT' -ClassName 'SCCMZone'
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName,
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNullorEmpty()]
            [string]$PropertyName = '*',
            [Parameter(Mandatory=$false,Position=3)]
            [ValidateNotNullorEmpty()]
            [string]$PropertyValue,
            [Parameter(Mandatory=$false,Position=4)]
            [ValidateNotNullorEmpty()]
            [string]$QualifierName,
            [Parameter(Mandatory=$false,ValueFromPipeline,Position=5)]
            [ValidateNotNullorEmpty()]
            [PSCustomObject]$Property = @()
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if class exists
                $ClassTest = Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'SilentlyContinue'
    
                ## If no class is found, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $ClassTest) {
                    $ClassNotFoundErr = "No class [$ClassName] found in namespace [$Namespace]."
                    Write-Log -Message $ClassNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $ClassNotFoundErr -Category 'ObjectNotFound'
                }
    
                ## Get class properties
                $WmiProperty = (Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'SilentlyContinue' | Select-Object *).CimClassProperties | Where-Object -Property Name -like $PropertyName
    
                ## Get class property based on specified parameters
                If ($Property) {
    
                    #  Compare all specified properties and return only properties that match Name, Value and CimType.
                    $GetProperty = Compare-Object -ReferenceObject $Property -DifferenceObject $WmiProperty -Property Name, Value, CimType -IncludeEqual -ExcludeDifferent -PassThru
    
                }
                ElseIf ($PropertyValue -and $QualifierName) {
                    $GetProperty = $WmiProperty | Where-Object { ($_.Value -like $PropertyValue) -and ($_.Qualifiers.Name -like $QualifierName) }
                }
                ElseIf ($PropertyValue) {
                    $GetProperty = $WmiProperty | Where-Object -Property Value -like $PropertyValue
                }
                ElseIf ($QualifierName) {
                    $GetProperty = $WmiProperty | Where-Object { $_.Qualifiers.Name -like $QualifierName }
                }
                Else {
                    $GetProperty = $WmiProperty
                }
    
                ## If no matching properties are found, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $GetProperty) {
                    $PropertyNotFoundErr = "No property [$PropertyName] found for class [$Namespace`:$ClassName]."
                    Write-Log -Message $PropertyNotFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $PropertyNotFoundErr -Category 'ObjectNotFound'
                }
            }
            Catch {
                Write-Log -Message "Failed to retrieve wmi class [$Namespace`:$ClassName] properties. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $GetProperty
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function Remove-WmiClass {
    <#
    .SYNOPSISl
        This function is used to remove a WMI class.
    .DESCRIPTION
        This function is used to remove a WMI class by name.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI class. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name to remove. Can be piped.
    .PARAMETER RemoveAll
        This switch is used to remove all namespace classes.
    .EXAMPLE
        Remove-WmiClass -Namespace 'ROOT' -ClassName 'SCCMZone','SCCMZoneBlog'
    .EXAMPLE
        'SCCMZone','SCCMZoneBlog' | Remove-WmiClass -Namespace 'ROOT'
    .EXAMPLE
        Remove-WmiClass -Namespace 'ROOT' -RemoveAll
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$false,ValueFromPipeline,Position=1)]
            [ValidateNotNullorEmpty()]
            [string[]]$ClassName,
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNullorEmpty()]
            [switch]$RemoveAll = $false
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Get classes names
                [string[]]$WmiClassNames = (Get-WmiClass -Namespace $Namespace -ErrorAction 'Stop').CimClassName
    
                ## Add classes to deletion string array depending on selected options
                If ($RemoveAll) {
                    $ClassNamesToDelete = $WmiClassNames
                }
                ElseIf ($ClassName) {
                    $ClassNamesToDelete = $WmiClassNames | Where-Object { $_ -in $ClassName }
                }
                Else {
                    $ClassNameIsNullErr = "ClassName cannot be `$null if -RemoveAll is not specified."
                    Write-Log -Message $ClassNameIsNullErr -Severity 3 -Source ${CmdletName}
                    Write-Error -Message $ClassNameIsNullErr -Category 'InvalidArgument'
                }
    
                ## Remove classes
                If ($ClassNamesToDelete) {
                    $ClassNamesToDelete | Foreach-Object {
    
                        #  Create the class object
                        [wmiclass]$ClassObject = New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList @("\\.\$Namespace`:$_")
    
                        #  Remove class
                        $null = $ClassObject.Delete()
                        $ClassObject.Dispose()
                    }
                }
                Else {
                    $ClassNotFoundErr = "No matching class [$ClassName] found for namespace [$Namespace]."
                    Write-Log -Message $ClassNotFoundErr -Severity 2 -Source ${CmdletName}
                    Write-Error -Message $ClassNotFoundErr -Category 'ObjectNotFound'
                }
            }
            Catch {
                Write-Log -Message "Failed to remove class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {}
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function Rename-WmiClass {
    <#
    .SYNOPSIS
        This function is used to rename a WMI class.
    .DESCRIPTION
        This function is used to rename a WMI class by creating a new class, copying all existing properties and instances to it and removing the old one.
    .PARAMETER Namespace
        Specifies the namespace for the class. Default is: ROOT\cimv2.
    .PARAMETER Name
        Specifies the class name to be renamed.
    .PARAMETER NewName
        Specifies the new class name.
    .EXAMPLE
        Rename-WmiClass -Namespace 'ROOT\cimv2' -Name 'SCCM' -NewName 'SCCMZone'
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$Name,
            [Parameter(Mandatory=$true,Position=2)]
            [ValidateNotNullorEmpty()]
            [string]$NewName
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Set class paths
                $ClassPathSource = "$Namespace`:$Name"
                $ClassPathDestination =  "$Namespace`:$NewName"
    
                ## Check if the source class exists
                Get-WmiClass -Namespace $ClassPathSource -ErrorVariable 'Stop'
    
                ## Create the new class but throw an error if it already exists
                New-WmiClass -Namespace $Namespace -ClassName $NewName -ErrorAction 'Stop'
    
                ## Copy the old class
                #  Copy class qualifiers
                Copy-WmiClassQualifier -ClassPathSource $ClassPathSource -ClassPathDestination $ClassPathDestination -ErrorAction 'Stop'
    
                #  Copy class properties
                Copy-WmiProperty -ClassPathSource $ClassPathSource -ClassPathDestination $ClassPathDestination -ErrorAction 'Stop'
    
                #  Copy class instances
                Copy-WmiInstance -ClassPathSource $ClassPathSource -ClassPathDestination $ClassPathDestination -ErrorAction 'Stop'
    
                ## Remove the old class
                Remove-WmiClass -Namespace $Namespace -ClassName $Name -ErrorAction 'Stop'
    
                ## Write success message to console
                Write-Log -Message "Succesfully renamed class [$ClassPathSource -> $ClassPathDestination]" -Source ${CmdletName}
            }
            Catch {
                Write-Log -Message "Failed to rename class. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {}
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function New-WmiProperty {
    <#
    .SYNOPSIS
        This function is used to add properties to a WMI class.
    .DESCRIPTION
        This function is used to add custom properties to a WMI class.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI namespace. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class name for which to add the properties.
    .PARAMETER PropertyName
        Specifies the property name.
    .PARAMETER PropertyType
        Specifies the property type.
    .PARAMETER Qualifiers
        Specifies one ore more property qualifiers using qualifier name and value only. You can omit this parameter or enter one or more items in the hashtable.
        You can also specify a string but you must separate the name and value with a new line character (`n). This parameter can also be piped.
        The qualifiers will be added with these default flavors:
            IsAmended = $false
            PropagatesToInstance = $true
            PropagatesToSubClass = $false
            IsOverridable = $true
    .PARAMETER Key
        Specifies if the property is key. Default is: false.(Optional)
    .EXAMPLE
        [hashtable]$Qualifiers = @{
            Key = $true
            Static = $true
            Description = 'SCCMZone Blog'
        }
        New-WmiProperty -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -PropertyName 'Website' -PropertyType 'String' -Qualifiers $Qualifiers
    .EXAMPLE
        "Key = $true `n Description = SCCMZone Blog" | New-WmiProperty -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -PropertyName 'Website' -PropertyType 'String'
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName,
            [Parameter(Mandatory=$true,Position=2)]
            [ValidateNotNullorEmpty()]
            [string]$PropertyName,
            [Parameter(Mandatory=$true,Position=3)]
            [ValidateNotNullorEmpty()]
            [string]$PropertyType,
            [Parameter(Mandatory=$false,ValueFromPipeline,Position=4)]
            [ValidateNotNullorEmpty()]
            [PSCustomObject]$Qualifiers = @()
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the class exists
                $null = Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'Stop'
    
                ## Check if the property exist
                $WmiPropertyTest = Get-WmiProperty -Namespace $Namespace -ClassName $ClassName -PropertyName $PropertyName -ErrorAction 'SilentlyContinue'
    
                ## Create the property if it does not exist
                If (-not $WmiPropertyTest) {
    
                    #  Set property to array if specified
                    If ($PropertyType -match 'Array') {
                        $PropertyType = $PropertyType.Replace('Array','')
                        $PropertyIsArray = $true
                    }
                    Else {
                        $PropertyIsArray = $false
                    }
    
                    #  Create the ManagementClass object
                    [wmiclass]$ClassObject = New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList @("\\.\$Namespace`:$ClassName")
    
                    #  Add class property
                    $ClassObject.Properties.Add($PropertyName, [System.Management.CimType]$PropertyType, $PropertyIsArray)
    
                    #  Write class object
                    $NewProperty = $ClassObject.Put()
                    $ClassObject.Dispose()
    
                    ## On property creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                    If (-not $NewProperty) {
    
                        #  Error handling and logging
                        $NewPropertyErr = "Failed create property [$PropertyName] for Class [$Namespace`:$ClassName]."
                        Write-Log -Message $NewPropertyErr -Severity 3 -Source ${CmdletName} -DebugMessage
                        Write-Error -Message $NewPropertyErr -Category 'InvalidResult'
                    }
    
                    ## Set property qualifiers one by one if specified
                    If ($Qualifiers) {
                        #  Convert to a hashtable format accepted by Set-WmiPropertyQualifier. Name = QualifierName and Value = QualifierValue are expected.
                        $Qualifiers.Keys | ForEach-Object {
                            [hashtable]$PropertyQualifier = @{ Name = $_; Value = $Qualifiers.Item($_) }
                            #  Set qualifier
                            $null = Set-WmiPropertyQualifier -Namespace $Namespace -ClassName $ClassName -PropertyName $PropertyName -Qualifier $PropertyQualifier -ErrorAction 'Stop'
                        }
                    }
                }
                Else {
                    $PropertyAlreadyExistsErr = "Property [$PropertyName] already present for class [$Namespace`:$ClassName]."
                    Write-Log -Message $PropertyAlreadyExistsErr  -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $PropertyAlreadyExistsErr -Category 'ResourceExists'
                }
            }
            Catch {
                Write-Log -Message "Failed to create property for class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $NewProperty
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function New-WmiClass {
    <#
    .SYNOPSIS
        This function is used to create a WMI class.
    .DESCRIPTION
        This function is used to create a WMI class with custom properties.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI namespace. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the name for the new class.
    .PARAMETER Qualifiers
        Specifies one ore more property qualifiers using qualifier name and value only. You can omit this parameter or enter one or more items in the hashtable.
        You can also specify a string but you must separate the name and value with a new line character (`n). This parameter can also be piped.
        The qualifiers will be added with these default values and flavors:
            Static = $true
            IsAmended = $false
            PropagatesToInstance = $true
            PropagatesToSubClass = $false
            IsOverridable = $true
    .PARAMETER CreateDestination
        This switch is used to create destination namespace.
    .EXAMPLE
        [hashtable]$Qualifiers = @{
            Key = $true
            Static = $true
            Description = 'SCCMZone Blog'
        }
        New-WmiClass -Namespace 'ROOT' -ClassName 'SCCMZone' -Qualifiers $Qualifiers
    .EXAMPLE
        "Key = $true `n Static = $true `n Description = SCCMZone Blog" | New-WmiClass -Namespace 'ROOT' -ClassName 'SCCMZone'
    .EXAMPLE
        New-WmiClass -Namespace 'ROOT\SCCM' -ClassName 'SCCMZone' -CreateDestination
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName,
            [Parameter(Mandatory=$false,ValueFromPipeline,Position=2)]
            [ValidateNotNullorEmpty()]
            [PSCustomObject]$Qualifiers = @("Static = $true"),
            [Parameter(Mandatory=$false,Position=3)]
            [ValidateNotNullorEmpty()]
            [switch]$CreateDestination = $false
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the class exists
                [boolean]$ClassTest = Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'SilentlyContinue'
    
                ## Check if the namespace exists
                [boolean]$NamespaceTest = Get-WmiNamespace -Namespace $Namespace -ErrorAction 'SilentlyContinue'
    
                ## Create destination namespace if specified, otherwise throw error if -ErrorAction 'Stop' is specified
                If ((-not $NamespaceTest) -and $CreateDestination) {
                    $null = New-WmiNamespace $Namespace -CreateSubTree -ErrorAction 'Stop'
                }
                ElseIf (-not $NamespaceTest) {
                    $NamespaceNotFoundErr = "Namespace [$Namespace] does not exist. Use the -CreateDestination switch to create namespace."
                    Write-Log -Message $NamespaceNotFoundErr -Severity 3 -Source ${CmdletName}
                    Write-Error -Message $NamespaceNotFoundErr -Category 'ObjectNotFound'
                }
    
                ## Create class if it does not exist
                If (-not $ClassTest) {
    
                    #  Create class object
                    [wmiclass]$ClassObject = New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList @("\\.\$Namespace`:__CLASS", [String]::Empty, $null)
                    $ClassObject.Name = $ClassName
    
                    #  Write the class and dispose of the class object
                    $NewClass = $ClassObject.Put()
                    $ClassObject.Dispose()
    
                    #  On class creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                    If (-not $NewClass) {
    
                        #  Error handling and logging
                        $NewClassErr = "Failed to create class [$ClassName] in namespace [$Namespace]."
                        Write-Log -Message $NewClassErr -Severity 3 -Source ${CmdletName} -DebugMessage
                        Write-Error -Message $NewClassErr -Category 'InvalidResult'
                    }
    
                    ## If input qualifier is not a hashtable convert string input to hashtable
                    If ($Qualifiers -isnot [hashtable]) {
                        $Qualifiers = $Qualifiers | ConvertFrom-StringData
                    }
    
                    ## Set property qualifiers one by one if specified, otherwise set default qualifier name, value and flavors
                    If ($Qualifiers) {
                        #  Convert to a hashtable format accepted by Set-WmiClassQualifier. Name = QualifierName and Value = QualifierValue are expected.
                        $Qualifiers.Keys | ForEach-Object {
                            [hashtable]$PropertyQualifier = @{ Name = $_; Value = $Qualifiers.Item($_) }
                            #  Set qualifier
                            $null = Set-WmiClassQualifier -Namespace $Namespace -ClassName $ClassName -Qualifier $PropertyQualifier -ErrorAction 'Stop'
                        }
                    }
                    Else {
                        $null = Set-WmiClassQualifier -Namespace $Namespace -ClassName $ClassName -ErrorAction 'Stop'
                    }
                }
                Else {
                    $ClassAlreadyExistsErr = "Failed to create class [$Namespace`:$ClassName]. Class already exists."
                    Write-Log -Message $ClassAlreadyExistsErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $ClassAlreadyExistsErr -Category 'ResourceExists'
                }
            }
            Catch {
                Write-Log -Message "Failed to create class [$ClassName] in namespace [$Namespace]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $NewClass
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function New-WmiNamespace {
    <#
    .SYNOPSIS
        This function is used to create a new WMI namespace.
    .DESCRIPTION
        This function is used to create a new WMI namespace.
    .PARAMETER Namespace
        Specifies the namespace to create.
    .PARAMETER CreateSubTree
        This swith is used to create the whole namespace sub tree if it does not exist.
    .EXAMPLE
        New-WmiNamespace -Namespace 'ROOT\SCCM'
    .EXAMPLE
        New-WmiNamespace -Namespace 'ROOT\SCCM\SCCMZone\Blog' -CreateSubTree
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$true,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace,
            [Parameter(Mandatory=$false,Position=1)]
            [ValidateNotNullorEmpty()]
            [switch]$CreateSubTree = $false
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if the namespace exists
                $WmiNamespace = Get-WmiNamespace -Namespace $Namespace -ErrorAction 'SilentlyContinue'
    
                ## Create Namespace if it does not exist
                If (-not $WmiNamespace) {
    
                    #  Split path into it's components
                    $NamespacePaths = $Namespace.Split('\')
    
                    #  Assigning root namespace, just for show, should always be 'ROOT'
                    [string]$Path = $NamespacePaths[0]
    
                    #  Initialize NamespacePathsObject
                    [PSCustomObject]$NamespacePathsObject = @()
    
                    #  Parsing path components and assemle individual paths
                    For ($i = 1; $i -le $($NamespacePaths.Length -1); $i++ ) {
                        $Path += '\' + $NamespacePaths[$i]
    
                        #  Assembing path props and add them to the NamspacePathsObject
                        $PathProps = [ordered]@{ Name = $(Split-Path -Path $Path) ; Value = $(Split-Path -Path $Path -Leaf) }
                        $NamespacePathsObject += $PathProps
                    }
    
                    #  Split path into it's components
                    $NamespacePaths = $Namespace.Split('\')
    
                    #  Assigning root namespace, just for show, should always be 'ROOT'
                    [string]$Path = $NamespacePaths[0]
    
                    #  Initialize NamespacePathsObject
                    [PSCustomObject]$NamespacePathsObject = @()
    
                    #  Parsing path components and assemle individual paths
                    For ($i = 1; $i -le $($NamespacePaths.Length -1); $i++ ) {
                        $Path += '\' + $NamespacePaths[$i]
    
                        #  Assembing path props and add them to the NamspacePathsObject
                        $PathProps = [ordered]@{
                            'NamespacePath' = $(Split-Path -Path $Path)
                            'NamespaceName' = $(Split-Path -Path $Path -Leaf)
                            'NamespaceTest' = [boolean]$(Get-WmiNamespace -Namespace $Path -ErrorAction 'SilentlyContinue')
                        }
                        $NamespacePathsObject += [PSCustomObject]$PathProps
                    }
    
                    #  If the path does not contain missing subnamespaces or the -CreateSubTree switch is specified create namespace or namespaces
                    If ((($NamespacePathsObject -match $false).Count -eq 1 ) -or $CreateSubTree) {
    
                        #  Create each namespace in path one by one
                        $NamespacePathsObject | ForEach-Object {
    
                            #  Check if we need to create the namespace
                            If (-not $_.NamespaceTest) {
                                #  Create namespace object and assign namespace name
                                $NameSpaceObject = (New-Object -TypeName 'System.Management.ManagementClass' -ArgumentList "\\.\$($_.NameSpacePath)`:__NAMESPACE").CreateInstance()
                                $NameSpaceObject.Name = $_.NamespaceName
    
                                #  Write the namespace object
                                $NewNamespace = $NameSpaceObject.Put()
                                $NameSpaceObject.Dispose()
                            }
                            Else {
                                Write-Log -Message "Namespace [$($_.NamespacePath)`\$($_.NamespaceName)] already exists." -Severity 2 -Source ${CmdletName} -DebugMessage
                            }
                        }
    
                        #  On namespace creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                        If (-not $NewNamespace) {
                            $CreateNamespaceErr = "Failed to create namespace [$($_.NameSpacePath)`\$($_.NamespaceName)]."
                            Write-Log -Message $CreateNamespaceErr -Severity 3 -Source ${CmdletName} -DebugMessage
                            Write-Error -Message $CreateNamespaceErr -Category 'InvalidResult'
                        }
                    }
                    ElseIf (($($NamespacePathsObject -match $false).Count -gt 1)) {
                        $SubNamespaceFoundErr = "Child namespace detected in namespace path [$Namespace]. Use the -CreateSubtree switch to create the whole path."
                        Write-Log -Message $SubNamespaceFoundErr -Severity 2 -Source ${CmdletName} -DebugMessage
                        Write-Error -Message $SubNamespaceFoundErr -Category 'InvalidOperation'
                    }
                }
                Else {
                    $NamespaceAlreadyExistsErr = "Failed to create namespace. [$Namespace] already exists."
                    Write-Log -Message $NamespaceAlreadyExistsErr -Severity 2 -Source ${CmdletName} -DebugMessage
                    Write-Error -Message $NamespaceAlreadyExistsErr -Category 'ResourceExists'
                }
            }
            Catch {
                Write-Log -Message "Failed to create namespace [$Namespace]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $NewNamespace
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
Function New-WmiInstance {
    <#
    .SYNOPSIS
        This function is used to create a WMI Instance.
    .DESCRIPTION
        This function is used to create a WMI Instance using CIM.
    .PARAMETER Namespace
        Specifies the namespace where to search for the WMI class. Default is: 'ROOT\cimv2'.
    .PARAMETER ClassName
        Specifies the class where to create the new WMI instance.
    .PARAMETER Key
        Specifies properties that are used as keys (Optional).
    .PARAMETER Property
        Specifies the class instance Properties or Values. You can also specify a string but you must separate the name and value with a new line character (`n).
        This parameter can also be piped.
    .EXAMPLE
        [hashtable]$Property = @{
            'ServerPort' = '89'
            'ServerIP' = '11.11.11.11'
            'Source' = 'File1'
            'Date' = $(Get-Date)
        }
        New-WmiInstance -Namespace 'ROOT' -ClassName 'SCCMZone' -Key 'File1' -Property $Property
    .EXAMPLE
        "Server Port = 89 `n ServerIp = 11.11.11.11 `n Source = File `n Date = $(GetDate)" | New-WmiInstance -Namespace 'ROOT' -ClassName 'SCCMZone' -Property $Property
    .NOTES
        This is a module function and can typically be called directly.
    .LINK
        https://sccm-zone.com
    .LINK
        https://github.com/JhonnyTerminus/SCCM
    #>
        [CmdletBinding()]
        Param (
            [Parameter(Mandatory=$false,Position=0)]
            [ValidateNotNullorEmpty()]
            [string]$Namespace = 'ROOT\cimv2',
            [Parameter(Mandatory=$true,Position=1)]
            [ValidateNotNullorEmpty()]
            [string]$ClassName,
            [Parameter(Mandatory=$false,Position=2)]
            [ValidateNotNullorEmpty()]
            [string[]]$Key,
            [Parameter(Mandatory=$true,ValueFromPipeline,Position=3)]
            [ValidateNotNullorEmpty()]
            [PSCustomObject]$Property
        )
    
        Begin {
            ## Get the name of this function and write header
            [string]${CmdletName} = $PSCmdlet.MyInvocation.MyCommand.Name
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -CmdletBoundParameters $PSBoundParameters -Header
        }
        Process {
            Try {
    
                ## Check if class exists
                $null = Get-WmiClass -Namespace $Namespace -ClassName $ClassName -ErrorAction 'Stop'
    
                ## If input qualifier is not a hashtable convert string input to hashtable
                If ($Property -isnot [hashtable]) {
                    $Property = $Property | ConvertFrom-StringData
                }
    
                ## Create instance
                If ($Key) {
                    $NewInstance = New-CimInstance -Namespace $Namespace -ClassName $ClassName -Key $Key -Property $Property
                }
                Else {
                    $NewInstance = New-CimInstance -Namespace $Namespace -ClassName $ClassName -Property $Property
                }
    
                ## On instance creation failure, write debug message and optionally throw error if -ErrorAction 'Stop' is specified
                If (-not $NewInstance) {
                    Write-Log -Message "Failed to create instance in class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName} -DebugMessage
                }
            }
            Catch {
                Write-Log -Message "Failed to create instance in class [$Namespace`:$ClassName]. `n$(Resolve-Error)" -Severity 3 -Source ${CmdletName}
                Break
            }
            Finally {
                Write-Output -InputObject $NewInstance
            }
        }
        End {
            Write-FunctionHeaderOrFooter -CmdletName ${CmdletName} -Footer
        }
}
function Get-IPGeolocation {
    $IPAddress = (Invoke-RestMethod -Method Get -Uri "https://api.bigdatacloud.net/data/client-ip").ipString
    $GeoData = Invoke-RestMethod -Method Get -Uri "https://api.bigdatacloud.net/data/ip-geolocation-full?ip=$IPAddress&localityLanguage=fr&key=62895cdce65746bc8b852e66d7627234"
    return $GeoData
}

#----------------------------------------------------------[Declarations]----------------------------------------------------------
$WMINamespace = "ROOT\NABLE"
$WMIClass = "GEOLOCATION"
#-----------------------------------------------------------[Execution]------------------------------------------------------------

#Retrieve Geo Location Data
$GeoData = Get-IPGeolocation

#Check if the WMI namespace exists
$NableWMINamespace = Get-WmiNamespace -Namespace $WMINamespace
if ($null -ne $NableWMINamespace) {
    #The namespace already exist, check if the class exist too
    $GeoLocationClass = Get-WmiClass -Namespace $WMINamespace -ClassName $WMIClass
    if ($null -ne $GeoLocationClass) {
        #remove the old WMI Class
        Remove-WmiClass -Namespace $WMINamespace -ClassName $WMIClass
        #Create WMI Class
        New-WmiClass -Namespace $WMINamespace -ClassName $WMIClass
    }
}else {
    #Create WMI Nanespace
    New-WmiNamespace -Namespace $WMINamespace
    New-WmiClass -Namespace $WMINamespace -ClassName $WMIClass
}

#reverse-geocode-with-timezone
#$GeoData = Invoke-RestMethod -Method Get -Uri "https://api.bigdatacloud.net/data/reverse-geocode-with-timezone?latitude=45,510&longitude=-73,570&localityLanguage=fr&key=62895cdce65746bc8b852e66d7627234"


#$Latitude = 52.15337
#$Longitude = -107.04108
#Invoke-RestMethod -Method Get -Uri "https://api.bigdatacloud.net/data/reverse-geocode-client?latitude=52.15337&longitude=-107.04108&localityLanguage=fr"

#Create WMI Nanespace
#New-WmiNamespace -Namespace $WMINamespace

#Create WMI Class
#New-WmiClass -Namespace $WMINamespace -ClassName $WMIClass

#Add the properties to the GEOLOCATION WMI Class
[hashtable]$Qualifiers = @{
    Key = $true
    Static = $true
}
#NOTE:The key qualifier need to be assigned to one property that will serve as index
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'Name' -PropertyType 'String' -Qualifiers $Qualifiers
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'RegionAdm' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'IP' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'City' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'Country' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'ISP' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'Latitude' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'Longitude' -PropertyType 'String'
New-WmiProperty -Namespace $WMINamespace -ClassName $WMIClass -PropertyName 'Timezone' -PropertyType 'String'

[string]$DeviceIP           = $GeoData.ip
[string]$DeviceRegionAdm    = $GeoData.location.localityInfo.administrative[2].name
[string]$DeviceCity         = $GeoData.location.city
[string]$DeviceCountry      = $GeoData.country.name
[string]$DeviceISP          = $GeoData.network.carriers.organisation
#if ($null -or "ValueNotSet" -ne $pDeviceLatitude) { [string]$DeviceLatitude = $pDeviceLatitude } else { [string]$DeviceLatitude  = $GeoData.confidenceArea.latitude[0] }
#if ($null -or "ValueNotSet" -ne $pDeviceLongitude) { [string]$DeviceLongitude = $pDeviceLongitude } else { [string]$DeviceLongitude = $GeoData.confidenceArea.longitude[0] }
[string]$DeviceLatitude  = $GeoData.confidenceArea.latitude[0]
[string]$DeviceLongitude = $GeoData.confidenceArea.longitude[0]
[string]$DeviceTimezone     = $GeoData.location.timeZone.displayName

#valeurs interessantes
[hashtable]$Property = @{
    'Name' = "GEOLOCATION_DATA"
    'IP' = $DeviceIP
    'RegionAdm' = $DeviceRegionAdm
    'City' = $DeviceCity
    'Country' = $DeviceCountry
    'ISP' = $DeviceISP
    'Latitude' = $DeviceLatitude
    'Longitude' = $DeviceLongitude
    'Timezone' = $DeviceTimezone
}

New-WmiInstance -Namespace $WMINamespace -ClassName $WMIClass -Property $Property



