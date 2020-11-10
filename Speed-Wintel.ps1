# All-in-One Set of tools for agile wintel admins

# Parse myself to get the list of functions:

type .\Speed-Wintel.ps1 | select -skip 10 |  Select-String "function" -SimpleMatch


function global:Count-Files {robocopy $args[0] c:\temp /S /L /W:0 /R:0 /NP /NDL /NFL }



function global:Show-HealthCheckCode4KSH { #parameter is list of hostnames
    [Cmdletbinding()]
    Param(
        [parameter(ValueFromPipeline=$true)] [string]$InputList 
    )

process {
   

   $hostname = ($inputlist).tolower();
   $output =  "t=$($hostname)"+' ;tacmd executecommand -m spa_$t:NT -v -o -e -c '+"'"+'powershell.exe gwmi win32_service ^| ? startmode -eq Auto ^| ? state -ne Running ^| ft name,exitcode, displayname -wrap'+"'"
   $output
   }


}



function global:Select-ExpandedProperty {
    [Cmdletbinding()]
    Param(
        [parameter(Mandatory=$true)] [String] $Value,
        [parameter(ValueFromPipeline=$true)] $InputObject
    )
    Process{

    Select-Object -InputObject $InputObject -ExpandProperty $Value
    
    }
    }


"`n`n Run this command to make expanding a property easier:" 
"`nSet-Alias ~ Select-ExpandProperty"

function global:Dir20 {param ($mask)
dir $mask | sort lastw* | select -last 20
}

function global:Dir50 {param ($mask)
dir $mask | sort lastw* | select -last 50
}


function global:Get-LoggedUser{ param ($server)

    $header=@('USERNAME', 'SESSIONNAME', 'ID', 'STATE', 'IDLE TIME', 'LOGON TIME')


    try{
        $result=if($server){query user /server:$server}
                else {query user}

        if ($result -notlike "*No User exist*") {
        #lets not assume the column width are the same every time
        $indexes = $header | ForEach-Object {($result[0]).IndexOf(" $_")}        

        #process each row to a PS object, skip the header
        for($row=1; $row -lt $result.Count; $row++){
            $obj=New-Object psobject

            for($i=0; $i -lt $header.Count; $i++){
                $begin=$indexes[$i]
                $end=if($i -lt $header.Count-1) {$indexes[$i+1]} else {$result[$row].length}

                $obj | Add-Member NoteProperty $header[$i] ($result[$row].substring($begin, $end-$begin)).trim()
            }
            
            Write-Output $obj
        }}
    }

    catch{
        
    }
}

function global:ConvertTo-Scriptblock { # param ( $string )
# to Convert a String into a Script Block
Param(
[Parameter(
Mandatory = $true,
ParameterSetName = '',
ValueFromPipeline = $true)]
[string]$string
)
$scriptBlock = [scriptblock]::Create($string)
return $scriptBlock
}


function global:0Get-UserDetails { # param ( $user, $domain )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] [string]$user,
      [string]$domain = "global.to"
    )
    if ($domain -eq "nhy") {$domain = "nhy.hydro.com"}
    $dc = Get-ADDomainController -DomainName $domain -Discover -NextClosestSite
    $DCname = $dc.hostname[0]
    get-aduser $user -server $DCname -properties * | select * -excludeproperty userCertificate, msPKIDPAPIMasterKeys, msPKIAccountCredentials
    } #fn Get-UserDetails



function global:0Get-IBMUserDetailsByName { # param ( $user )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] $userInput
    )


  $userinput = $userinput.split("`n")
  $u2 = $userinput | % {$_.split(" ")}
  $y = 0;

  foreach ($u in $userinput)
      {

  $u3 = $u2[$y+1] + ", "+$u2[$y]
  $y+=2
  
  

    $fltstring =  'Displayname -like "*' + $u3 + '*"'
    $fltstring

    #$fltfinal = (global:ConvertTo-Scriptblock $fltstring).getnewclosure()

    $searchbase = "OU=ibm,DC=global,DC=to" 
   
    get-aduser -Filter $fltstring -properties CN,
Description,
DisplayName,
DistinguishedName,
Enabled,
HomeDirectory,
HomedirRequired,
HomeDrive,
LastBadPasswordAttempt,
LastLogonDate,
LockedOut,
# MemberOf,
Modified,
Name,
PasswordExpired,
PasswordLastSet,
PasswordNeverExpires,
PrimaryGroup,
pwdLastSet,
SamAccountName,
UserPrincipalName,
whenChanged,
whenCreated
     
     } # process each

    
    } #fn Get-IBMUserDetailsByName


    
function global:0Get-UserDetailsByName { # param ( $user )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] $userInput
    )


  $userinput = $userinput.split("`n")
  $u2 = $userinput | % {$_.split(" ")}
  $y = 0;

  foreach ($u in $userinput)
      {

  $u3 = $u2[$y+1] + ", "+$u2[$y]
  $y+=2
  
  

    $fltstring =  'Displayname -like "*' + $u3 + '*"'
    $fltstring

    #$fltfinal = (global:ConvertTo-Scriptblock $fltstring).getnewclosure()

    $searchbase = "DC=global,DC=to" 
   
    get-aduser -Filter $fltstring -properties CN,
Description,
DisplayName,
DistinguishedName,
Enabled,
HomeDirectory,
HomedirRequired,
HomeDrive,
LastBadPasswordAttempt,
LastLogonDate,
LockedOut,
# MemberOf,
Modified,
Name,
PasswordExpired,
PasswordLastSet,
PasswordNeverExpires,
PrimaryGroup,
pwdLastSet,
SamAccountName,
UserPrincipalName,
whenChanged,
whenCreated
     
     } # process each

    
    } #fn Get-UserDetailsByName


function global:0Get-UserGroupMembership { # param ( $user, $domain )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] [string]$user,
        [string]$domain = "global.to"
    )
    if ($domain -eq "nhy") {$domain = "nhy.hydro.com"}

    $dc = Get-ADDomainController -DomainName $domain -Discover -NextClosestSite
    $DCname = $dc.hostname[0] 
    (get-aduser $user -server $DCname -properties * | select * -expandproperty memberof).substring(3) | % {$_.split(",")[0]}
    } #fn Get-UserMembership


function global:Extract-ACL { # param ( $FullPath )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] [string]$fullPath
    )
    $SubReport=[psobject]@()
    
    $acl = Get-Acl $fullPath
    foreach ($Access in $acl.Access)
        {
            $Properties = [ordered]@{'QTreePath'=$FullPath;'Account'=$Access.IdentityReference;'Permissions'=$Access.FileSystemRights;'Inherited'=$Access.IsInherited}
            $SubReport += New-Object -TypeName PSObject -Property $Properties
        }
return $SubReport 
    
    } #fn Extract-ACL


function global:0Get-ADGroupMembersRecursive { # param ( $group )
    [Cmdletbinding()]
    Param(        
        [parameter(ValueFromPipeline=$true)] [string]$group
    )


   (get-adgroup $group | get-adgroupmember -recursive).samaccountname


    } #fn Get-ADGroupMembersRecursive


function Global:Get-TotalSize { # param ( $Path )
    [CmdletBinding(DefaultParameterSetName = "Path")]
    param(
        [Parameter(ParameterSetName = "Path",
                   Mandatory = $true,
                   ValueFromPipeline = $true,
                   ValueFromPipelineByPropertyName = $true,
                   Position = 0)]
            [Alias('Name', 'FullName')]
            [string[]] $Path,
        [int] $Precision = 4,
        [switch] $RoboOnly,
        [switch] $ComOnly,
        [Parameter(ParameterSetName = "LiteralPath",
                   Mandatory = $true,
                   Position = 0)] [string[]] $LiteralPath,
        [ValidateRange(1, 128)] [byte] $RoboThreadCount = 16)
    begin {
        if ($RoboOnly -and $ComOnly) {
            Write-Error -Message "You can't use both -ComOnly and -RoboOnly. Default is COM with a fallback to robocopy." -ErrorAction Stop
        }
        if (-not $RoboOnly) {
            $FSO = New-Object -ComObject Scripting.FileSystemObject -ErrorAction Stop
        }
         function Get-RoboFolderSizeInternal { # ignore this one
            [CmdletBinding()]
            param(
                # Paths to report size, file count, dir count, etc. for.
                [string[]] $Path,
                [int] $Precision = 4)
            begin {
                if (-not (Get-Command -Name robocopy -ErrorAction SilentlyContinue)) {
                    Write-Warning -Message "Fallback to robocopy failed because robocopy.exe could not be found. Path '$p'. $([datetime]::Now)."
                    return
                }
            }
            process {
                foreach ($p in $Path) {
                    Write-Verbose -Message "Processing path '$p' with Get-RoboFolderSizeInternal. $([datetime]::Now)."
                    $RoboCopyArgs = @("/L","/S","/NJH","/BYTES","/FP","/NC","/NDL","/TS","/XJ","/R:0","/W:0","/MT:$RoboThreadCount")
                    [datetime] $StartedTime = [datetime]::Now
                    [string] $Summary = robocopy $p NULL $RoboCopyArgs | Select-Object -Last 8
                    [datetime] $EndedTime = [datetime]::Now
                    [regex] $HeaderRegex = '\s+Total\s*Copied\s+Skipped\s+Mismatch\s+FAILED\s+Extras'
                    [regex] $DirLineRegex = 'Dirs\s*:\s*(?<DirCount>\d+)(?:\s+\d+){3}\s+(?<DirFailed>\d+)\s+\d+'
                    [regex] $FileLineRegex = 'Files\s*:\s*(?<FileCount>\d+)(?:\s+\d+){3}\s+(?<FileFailed>\d+)\s+\d+'
                    [regex] $BytesLineRegex = 'Bytes\s*:\s*(?<ByteCount>\d+)(?:\s+\d+){3}\s+(?<BytesFailed>\d+)\s+\d+'
                    [regex] $TimeLineRegex = 'Times\s*:\s*(?<TimeElapsed>\d+).*'
                    [regex] $EndedLineRegex = 'Ended\s*:\s*(?<EndedTime>.+)'
                    if ($Summary -match "$HeaderRegex\s+$DirLineRegex\s+$FileLineRegex\s+$BytesLineRegex\s+$TimeLineRegex\s+$EndedLineRegex") {
                        New-Object PSObject -Property @{
                            Path = $p
                            TotalBytes = [decimal] $Matches['ByteCount']
                            TotalMBytes = [math]::Round(([decimal] $Matches['ByteCount'] / 1MB), $Precision)
                            TotalGBytes = [math]::Round(([decimal] $Matches['ByteCount'] / 1GB), $Precision)
                            BytesFailed = [decimal] $Matches['BytesFailed']
                            DirCount = [decimal] $Matches['DirCount']
                            FileCount = [decimal] $Matches['FileCount']
                            DirFailed = [decimal] $Matches['DirFailed']
                            FileFailed  = [decimal] $Matches['FileFailed']
                            TimeElapsed = [math]::Round([decimal] ($EndedTime - $StartedTime).TotalSeconds, $Precision)
                            StartedTime = $StartedTime
                            EndedTime   = $EndedTime

                        } | Select-Object -Property Path, TotalBytes, TotalMBytes, TotalGBytes, DirCount, FileCount, DirFailed, FileFailed, TimeElapsed, StartedTime, EndedTime
                    }
                    else {
                        Write-Warning -Message "Path '$p' output from robocopy was not in an expected format."
                    }
                }
            }
        }
    }
    process {
        if ($PSCmdlet.ParameterSetName -eq "Path") {
            $Paths = @(Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath -ErrorAction SilentlyContinue)
        }
        else {
            $Paths = @(Get-Item -LiteralPath $LiteralPath | Select-Object -ExpandProperty FullName -ErrorAction SilentlyContinue)
        }
        foreach ($p in $Paths) {
            Write-Verbose -Message "Processing path '$p'. $([datetime]::Now)."
            if (-not (Test-Path -LiteralPath $p -PathType Container)) {
                Write-Warning -Message "$p does not exist or is a file and not a directory. Skipping."
                continue
            }
            # We know we can't have -ComOnly here if we have -RoboOnly.
            if ($RoboOnly) {
                Get-RoboFolderSizeInternal -Path $p -Precision $Precision
                continue
            }
            $ErrorActionPreference = 'Stop'
            try {
                $StartFSOTime = [datetime]::Now
                $TotalBytes = $FSO.GetFolder($p).Size
                $EndFSOTime = [datetime]::Now
                if ($null -eq $TotalBytes) {
                    if (-not $ComOnly) {
                        Get-RoboFolderSizeInternal -Path $p -Precision $Precision
                        continue
                    }
                    else {
                        Write-Warning -Message "Failed to retrieve folder size for path '$p': $($Error[0].Exception.Message)."
                    }
                }
            }
            catch {
                if ($_.Exception.Message -like '*PERMISSION*DENIED*') {
                    if (-not $ComOnly) {
                        Write-Verbose "Caught a permission denied. Trying robocopy."
                        Get-RoboFolderSizeInternal -Path $p -Precision $Precision
                        continue
                    }
                    else {
                        Write-Warning "Failed to process path '$p' due to a permission denied error: $($_.Exception.Message)"
                    }
                }
                Write-Warning -Message "Encountered an error while processing path '$p': $($_.Exception.Message)"
                continue
            }
            $ErrorActionPreference = 'Continue'
            New-Object PSObject -Property @{
                Path = $p
                TotalBytes = [decimal] $TotalBytes
                TotalMBytes = [math]::Round(([decimal] $TotalBytes / 1MB), $Precision)
                TotalGBytes = [math]::Round(([decimal] $TotalBytes / 1GB), $Precision)
                BytesFailed = $null
                DirCount = $null
                FileCount = $null
                DirFailed = $null
                FileFailed  = $null
                TimeElapsed = [math]::Round(([decimal] ($EndFSOTime - $StartFSOTime).TotalSeconds), $Precision)
                StartedTime = $StartFSOTime
                EndedTime = $EndFSOTime
            } | Select-Object -Property Path, TotalBytes, TotalMBytes, TotalGBytes, DirCount, FileCount, DirFailed, FileFailed, TimeElapsed, StartedTime, EndedTime
        }
    }
    end {
        if (-not $RoboOnly) {
            [void][System.Runtime.Interopservices.Marshal]::ReleaseComObject($FSO)
        }
        [gc]::Collect()
        [gc]::WaitForPendingFinalizers()
    }
}

"enjoy wintel admin work :}"


