#requires -version 2
<#
.SYNOPSIS
  Powershell client for ThunderDNS
.DESCRIPTION
  This is a Powershell client for ThunderDNS tool.
  It can forward TCP traffic over DNS protocol.
.PARAMETER -domain
    Your domain name, which is links to your ThunderDNS server
.PARAMETER -clientname
    Your client name, it may be helpful, when you get clients list in ThunderProxy (--clients option)
.PARAMETER -server
    Optional parameter. Your DNS server address. May be "localhost" to tests. If not provided, client uses standard
        system DNS-server.
.NOTES
  Author:         FBK CyberSecurity [Sergey Migalin]
  Creation Date:  August, 2018
  
.EXAMPLE
  ./client.ps1 -domain oversec.ru -clientname test
.EXAMPLE
  ./client.ps1 -domain oversec.ru -clientname test -server localhost
#>

#---------------------------------------------------------[Initialisations]--------------------------------------------------------

param([string] $domain,
      [string] $clientname,
      [string] $server = '',
      [int] $blockLength = 200,
      [int] $bufferSize = 1024,
      [bool] $debug = $false)


#----------------------------------------------------------[Declarations]----------------------------------------------------------

#Script Version
$sScriptVersion = "0.1.4 alpha"

$MaximumBlockLength = $blockLength
$BufferSize = $bufferSize

$Actions = @{Register='0'; Request='1'; Reply='2'; Delete='3'}
$Dot = '.'

if ($debug)
{
    $DebugPreference = 'Continue'
} else {
    $DebugPreference = 'SilentlyContinue'
}


#-----------------------------------------------------------[Functions]------------------------------------------------------------

Function Random-String{

    Param([int]$Length)

    Process{
        return ([char[]]([char]'a'..[char]'z') + 0..9 | sort {get-random})[1..$Length] -join ''
    }

}


Function Get-DNS-TXT-value{
    Param([string]$text)
    Process{
        return [regex]::Matches($text, '"(.*)"') | %{$_.groups[1].value} | %{$_ -replace '([ "\t]+)',$('') }
    }
            
}

Function Get-TCP-Reply{
    Param($reader)

    Process{

        Try{
            $buf = [System.Byte[]]::CreateInstance([System.Byte], $BufferSize)
            $count =  $reader.Read($buf, 0, $BufferSize)
            $to = $count - 1
            return $buf[0..$to]
        }
        Catch {
            Write-Warning "Cannot read from TCP"
            return
        }
    }
}

Function Send-TCP-Request{

  Param($writer,
        $request) 

  Process{
        Try {
            $writer.Write($request, 0, $request.Length) | Out-Null
            return
        }

        Catch {
            Write-Warning "Cannot write TCP"
        }
  }
}

Function Connect-TCP{
    Param([string]$server,
          [string]$port)
    Process{
        Try{
            return New-Object System.Net.Sockets.TcpClient($server, $port)
        }

        Catch{
            return
        }
    }

}


Function Register{

  Param([string] $domain, 
        [string] $server,
        [string] $clientname)

  Process{
    $seed = Random-String -Length 7
    $act = $Actions.Register
    $text = &nslookup -q=TXT $act$seed$clientname$Dot$domain $server 2>$null 
    $text = Get-DNS-TXT-value -text $text
    $res = @{Id=$text.Substring(0,2); Key=$text.Substring(2,3)}
    return $res
  }
}


Function Del-user{
    
    Param([string] $domain,
          [string] $server,
          [string] $id)
    
    Process{
        $act = $Actions.Delete
        $seed = Random-String -Length 7
        $a = &nslookup -q=TXT $act$seed$id$Dot$domain $server 2>$null
        $a = Get-DNS-TXT-value -text $a
        $t1 = "12REM"
        if ($a.Substring(0,2) -eq $id) {
            Write-Host Success
        } else {
            Write-Host Not success
        }
    }

}


Function Reply{
    Param([string] $domain,
          [string] $server,
          [string] $id,
          [string] $key,
          [string] $reply)
    Process{
        
        $act = $Actions.Reply

        Write-Debug "Send Reply to DNS"

        for($i = 0; $i -lt $reply.Length / $MaximumBlockLength; $i += 1){

            #Start-Sleep -Milliseconds 500

            $seed = Random-String -Length 4
            $num = ([math]::floor($reply.Length / $MaximumBlockLength) - $i).ToString().PadLeft(3, '0')
            if ($reply.Length / $MaximumBlockLength -eq 1) {
                Write-Warning 'fix1'
                $num = "000"
            }

            Write-Progress -Activity "Reply to DNS" -Status "Remaining $num packets" -PercentComplete ($i * $MaximumBlockLength / $reply.Length * 100 )

            $part = $reply.Substring(($i * $MaximumBlockLength), 
                        [math]::min( $MaximumBlockLength, $reply.Length -  ($i * $MaximumBlockLength)))

            if ($part.Length -gt 189){
                $part = $part.Substring(0, 63) + "." + $part.Substring(63, 63) + "." + $part.Substring(126, 63) + "." + $part.Substring(189)
            } else {
                if ($part.Length -gt 126){
                    $part = $part.Substring(0, 63) + "." + $part.Substring(63, 63) + "." + $part.Substring(126)
                } else {
                    if ($part.Length -gt 63){
                        $part = $part.Substring(0, 63) + "." + $part.Substring(63)
                    }
                }
            }

            Write-Debug "Sending part $part . Request is $act$seed$id$num$Dot$part$Dot$domain $server"

            $text = &nslookup -q=TXT $act$seed$id$num$Dot$part$Dot$domain $server 2>$null | %{Get-DNS-TXT-value -text $_}

            Write-Debug "Status $text"

        }

        Write-Progress -Activity "Reply to DNS" -Completed -Status "Completed"
        
        return 

    }

}


Function Tun{

    Param([string] $domain,
          [string] $server = "",
          [string] $id,
          [string] $key)

    Process{

        $forwardToHost = ""
        $forwardToPort = ""

        $tcpConnection = ""
        $tcpStream = ""
        
        while($true)
        {
            $act = $Actions.Request

            #Start-Sleep -Milliseconds 500

            if ($tcpStream.DataAvailable){
                $reply = Get-TCP-Reply -reader $tcpStream
                #$reply = Gzip-Compress -byteArray $reply
                $reply = [System.Convert]::ToBase64String($reply)

                Write-Debug "Reply from TCP in Base64: $reply"

                Reply -domain $domain -server $server -id $id -key $key -reply $reply
            }

            $seed = Random-String -Length 7

            $text = &nslookup -q=TXT $act$seed$id$Dot$domain $server 2>$null

            $text = Get-DNS-TXT-value -text $text

            if (!$text){
                Write-Warning "Unable to get DNS info"
                continue
            }

            Write-Debug $text

            if ($text.StartsWith($id + "ND")){

                Write-Debug "No data, waiting"
                continue
            }

            $text = $text.Split(':')

            if (($forwardToHost -ne $text[0].Substring(2)) -or ($forwardToPort -ne $text[1]) -or !$tcpConnection.Connected){

                $forwardToHost = $text[0].Substring(2)
                $forwardToPort = $text[1]

                $tcpConnection = Connect-TCP -server $forwardToHost -port $forwardToPort

                if (!$tcpConnection.Connected) {
                    Write-Warning "Cannot establish TCP connection"
                    continue
                }
                $tcpStream = $tcpConnection.GetStream()
            }

            Write-Debug "Request came: $text[2]"

            $request = [System.Convert]::FromBase64String($text[2])
            #$request = Gzip-Decompress -byteArray $request
            Send-TCP-Request -writer $tcpStream -request $request

        }

    }

}

#-----------------------------------------------------------[Execution]------------------------------------------------------------


Write-Host ' ________________               _________         _______________   _________' -ForegroundColor Yellow -BackgroundColor Black
Write-Host ' ___/__  __/__/ /_____  ______________/ /______________/ __ \__/ | / //_ ___/' -ForegroundColor Yellow -BackgroundColor Black
Write-Host ' _____/ /____/ __ \  / / /_/ __ \/ __  /_/ _ \_/ __/ _/ / / /_/  |/ //____ \ ' -ForegroundColor Yellow -BackgroundColor Black
Write-Host ' ____/ /____/ / / / /_/ /_  / / / /_/ / /  __// /  __/ /_/ /_/ /|  / ____/ / ' -ForegroundColor Yellow -BackgroundColor Black
Write-Host ' ___/_/____/_/ /_/\__,_/ /_/ /_/\__,_/__\___//_/  __/_____/ /_/ |_/ /_____/  ' -ForegroundColor Yellow -BackgroundColor Black
Write-Host ''
Write-Host
Write-Host


if (!$domain -or !$clientname){

    Write-Host "Usage: ./client.ps1 -domain <DOMAIN> -clientname <CLIENTNAME> [-server <DN_SERVER>]" -ForegroundColor Yellow -BackgroundColor Black
    exit 1

}


Write-Host "DNSTunnel v$sScriptVersion was started" -ForegroundColor Yellow -BackgroundColor Black



Write-Host "Domain to forward: $domain" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "DN Server: $server" -ForegroundColor Cyan -BackgroundColor Black
Write-Host "Client name: $clientname" -ForegroundColor Cyan -BackgroundColor Black

$reg = Register -domain $domain -server $server -clientname $clientname

Write-Host "Client was registered: ID=" -ForegroundColor DarkGreen -BackgroundColor Black -NoNewline
Write-Host $reg.Id -ForegroundColor DarkGreen -BackgroundColor Black -NoNewline
Write-Host " KEY=" -ForegroundColor DarkGreen -BackgroundColor Black -NoNewline
Write-Host $reg.Key -ForegroundColor DarkGreen -BackgroundColor Black


try
{
    Tun -domain $domain -server $server -id $reg.Id -key $reg.Key
}
finally
{
    $id = $reg.Id
    write-host "Deleting user " $id
    Del-user -domain $domain -server $server -id $id
    
     
}


