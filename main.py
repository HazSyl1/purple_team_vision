import os
from crewai import Agent, Task, Crew, Process
from textwrap import dedent
from agents import CustomAgents
from tasks import CustomTasks

class CustomCrew:
    def __init__(self, var1):
        self.var1 = var1

    def run(self):
        # Define your custom agents and tasks in agents.py and tasks.py
        agents = CustomAgents()
        tasks = CustomTasks()

        # Define your custom agents and tasks here
        custom_agent_1 = agents.threat_intelligence_analyst()
        
        # custom_agent_2 = agents.agent_2_name()

        # Custom tasks include agent name and variables as input
        custom_task_1 = tasks.extract_ttps_task(
            custom_agent_1,
            var1=self.var1
        )

        # custom_task_2 = tasks.task_2_name(
        #     custom_agent_2,
        # )

        # Define your custom crew here
        crew = Crew(
            agents=[custom_agent_1,],
            tasks=[custom_task_1],
            verbose=True,
        )

        result = crew.kickoff()
        return result


# This is the main function that you will use to run your custom crew.
if __name__ == "__main__":
    print("## Welcome to Crew AI Template")
    # print("-------------------------------")
    # var1 = input(dedent("""Enter variable 1: """))
    # var2 = input(dedent("""Enter variable 2: """))
    var1=r"""
Brute Force Leads to BlueSky Ransomware
December 4, 2023
In December 2022, we observed an intrusion on a public-facing
MSSQL Server, which resulted in BlueSky ransomware. First
discovered in June 2022, BlueSky ransomware has code links to
Conti and Babuk ransomware.
While other reports point to malware downloads as initial access, in
this report the threat actors gained access via a MSSQL brute force
attack. They then leveraged Cobalt Strike and Tor2Mine to perform
post-exploitation activities. Within one hour of the threat actors
accessing the network, they deployed BlueSky ransomware
network wide.
Case Summary
In the month of December 2022, we observed a cluster of activity
targeting MSSQL servers. The activity started with brute force
password attempts for the MS SQL “sa” (System Administrator)
account on an internet facing server. Upon successfully discovering
the password, the threat actors enabled “xp_
cmdshell” on the SQL
server. The “xp_
cmdshell” allows users with sysadmin privilege to
execute shell commands on the host.
Using “xp_
cmdshell” the threat actors first executed a PowerShell
command on the SQL server. The command contained base64
encoded content, which, upon execution, established a connection
to a Cobalt Strike command and control server. This activity was
immediately followed by injection into the legitimate process
winlogon. The injected process then spawned PowerShell and cmd
to perform SMB scans and discovery using SMBexec.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 1/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
The PowerShell session was then seen making a connection to a
Tor2Mine stager server. This was followed by execution of a
PowerShell script which performed a variety of operations, such as
checking privileges of the active user, disabling of AV solutions,
and dropping of a miner payload named java.exe. Tor2Mine is a
Monero-mining campaign that is based on XMRigCC. Depending
upon the privileges of the user, the script also performs creation of
scheduled tasks and Windows services to maintain persistence on
the host.
Around 15 minutes after initial access, the threat actors then
moved laterally toward domain controllers and file shares using
remote service creation. These services were used to execute the
same PowerShell commands, download and execute the Tor2Mine
malware. Upon establishing access to one of the domain
controllers the threat actors performed similar activity as observed
on the beachhead.
After roughly 30 minutes after initial access, the BlueSky
ransomware binary was dropped and executed on the beachhead.
The execution worked as intended which resulted in the
ransomware spreading to all devices in the network over SMB. The
time to ransomware in this case was 32 minutes.
Threat Actor Profile:
Cobalt Strike
The Cobalt Strike server observed in this intrusion was first
observed on December 16th 2022 and remained active through
January 17th 2023. We saw the server then return for a second
time frame from April 6th 2023 though April 15th 2023. This data
was provided via the Threat Intel tracking services of The DFIR
Report.
Tor2Mine
The PowerShell scripts involved in this case as well as
infrastructure for the Tor2Mine server were observed being reused
in May 2023 with the PaperCut NG CVE-2023-27350 exploit as the
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 2/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
initial access source. In that intrusion no ransomware was
observed. The linked case data is available for All Intel subscribers
in event 21132 (c39d59d8-8bae-49f5-8b29-de5c13b61899).
Services
We offer multiple services including a Threat Feed service which
tracks Command and Control frameworks such as Cobalt Strike,
Sliver, BianLian, Metasploit, Empire, Havoc, etc. More information
on this service can be found here.
Our All Intel service includes private reports, exploit events, long
term infrastructure tracking, clustering, C2 configs, and other
curated intel.
We’ll be launching a private ruleset soon, if you’d like to get in at a
discounted rate for the beta, please Contact Us.
If you are interested in hearing more about our services, or would
like to talk about a free trial, please reach out using the Contact
Us page. We look forward to hearing from you.
Analysts
Analysis and reporting completed by @yatinwad
Initial Access
The initial access occurred via a brute-force attack, where the
threat actors mainly targeted the System Admin (“sa”) account.
During the intrusion, we observed over 10,000 failed attempts
before successful login.
SQL Server event ID 18456 Failure Audit Events in the Windows
application logs:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 3/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Successful Login:
Execution
In the next attack stage, the threat actors established a command
shell via Extended SQL Stored Procedure (xp_
cmdshell). This
process allows you to issue operating system commands directly to
the Windows command shell. To do this they enabled the feature
the MSSQL configuration:
The threat actor then executed a Cobalt Strike beacon and a
PowerShell script that has previously been identified by Sophos as
used in campaigns to deploy Tor2Mine malware.
The overall execution events are depicted in the below diagram:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 4/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
The first PowerShell script executed a command to download a
Cobalt Strike beacon.
This was followed by a second PowerShell execution for:
A connection was then established with the following Tor2Mine
server and URIs:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 5/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Tor2Mine uses a PowerShell script checking.ps1 to perform variety
of operations. The script first sets a variable named $priv and
$osver to check whether the active user is an administrator and the
operating system version respectively, in the first few lines.
It then attempts to pull down an additional script named kallen.ps1,
a PowerShell version of mimikatz from the Tor2Mine server.
It also consists of a function named “StopAV”
, where it tries to
disable antivirus solutions – in this case, MalwareBytes, Sophos
and Windows Defender.
Depending upon the result of the $priv variable, there are 2 routes
for the script: Privileged ”PrivTrue()“ and Non-Privileged
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 6/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
“PrivFalse()”
.
If the user is a privileged user, it first checks for the OS
architecture, then downloads appropriate version (in our case, x64)
of the miner and installs it as java.exe, in the
“C:\ProgramData\Oracle\Java” directory. It also installs a driver
named WinRing0x64.sys.
The function also creates multiple scheduled tasks and services
which have references to Tor2Mine miner java.exe, encoded
PowerShell commands and .hta files hosted on Tor2Mine servers.
In the case of the non-privileged function “PrivFalse()”
, it executes
a batch script “PrivFalse.bat” as scheduled tasks and also sets up
schtasks as seen in the “PrivTrue()” function.
In the last section, a script named del.ps1 is downloaded and
executed on the host as a scheduled task. The del.ps1 script has
been explored further in the Defense Evasion section.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 7/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Depending upon the output of the $priv variable, the execution flow
is as follows:
As the mimi function is commented, we didn’t observe any artifacts
related to kallen.ps1 script.
Persistence
To establish persistence in the network, multiple scheduled tasks
and Windows services were created on the beachhead and one of
the domain controllers. They reference the files dropped on the
compromised hosts and Tor2Mine servers.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 8/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Privilege Escalation
The threat actor was seen injecting code into legitimate process
winlogon.exe via CreateRemoteThread which can be detected
using Sysmon event ID 8.
During the intrusion the threat actor deployed XMrig miner which
loaded the driver WinRing0. This driver is deployed to assist the
miner in operations and has been in use since at least version
5.3.0.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 9/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Defense Evasion
The Windows Defender AV Real-Time Monitoring was disabled on
the beachhead and one of the domain controllers using Set-
MpPreference cmdlet.
The PowerShell script, checking.ps1, is explained in the Execution
section which contained other ways to disable AV, including registry
modifications and service disabling.
A PowerShell script named del.ps1 attempts to terminate system
utilities such as Process Explorer, Task Manager, Process Monitor,
and Daphne Task Manager.
In the script checking.ps1 the threat actor created 16 different tasks
on the hosts where Tor2Mine was deployed. These tasks were
named in a manner to try and blend in with various Windows tasks
that on the hosts:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 10/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
\Microsoft\Windows\MUI\LPupdate
\Microsoft\Windows\RamDiagnostic\Error Diagnostic
\Microsoft\Windows\.NET Framework\.NET Framework Cache
\Microsoft\Windows\.NET Framework\.NET Framework Cache
\Microsoft\Windows\.NET Framework\.NET Framework Cache
\Microsoft\Windows\Registry\RegBackup
\Microsoft\Windows\DiskCleanup\SlientDefragDisks
\Microsoft\Windows\.NET Framework\.NET Framework NGEN v
\Microsoft\Windows\EDP\EDP App Update Cache
\Microsoft\Windows\EDP\EDP App Lock Task
\Microsoft\Windows\UPnP\UPnPClient Task
\Microsoft\Windows\UPnP\UPnPHost
\Microsoft\Windows\Shell\WinShell
\Microsoft\Windows\Shell\WindowsShellUpdate
\Microsoft\Windows\Bluetooth\UpdateDeviceTask
\Microsoft\Windows\.NET Framework\.NET Framework Cache
Credential Access
Tor2Mine was used to access the LSASS memory space and the
access granted was 0x1010.
On the beachhead, we observed the execution of credential
dumping utility Invoke-PowerDump.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 11/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Discovery
During the course of the intrusion, we observed port discovery (port
445) activity from the beachhead. We attribute this to the
invocation of the PowerShell command Invoke-SMBExec. This was
likely executed as part of the Invoke-TheHash framework based on
other PowerShell modules observed.
Looking at the traffic from a network perspective we observed the
activity making DCE\RPC calls to the svcctl endpoint and the
named pipe \pipe\ntsvcs using the OpenSCManagerW operation.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 12/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
This appeared to be how they profiled the network layout and
remote hosts.
The threat actor was observed running whoami from the Tor2Mine
PowerShell process on the beachhead.
"C:\Windows\system32\whoami.exe" /user
Lateral Movement
The threat actors moved laterally toward the domain controllers
and file shares using Remote Service creation. The pattern
“%COMSPEC% /C “cmd /c powershell.exe” is associated with the
Cobalt Strike “psexec
_psh” jump module.
Decoding the command we can see the same PowerShell
download and execute as observed on the beachhead. The
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 13/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
hexadecimal value 0x53611451 corresponds to the IP address
83.97.20[.]81 which was the command and control server for the
Tor2Mine malware.
Command and Control
Tor2Mine Server:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 14/28
10/6/24, 12:30 AM {
SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
destination: { [-]
address: 83.97.20.81
as: { [-]
number: 9009
organization: { [-]
name: M247 Europe SRL
}
}
geo: { [-]
city_name: Bucharest
continent_name: Europe
country_iso_code: RO
country_name: Romania
location: { [+]
}
region_iso_code: RO-B
region_name: Bucuresti
}
ip: 83.97.20.81
port: 443
}
network.direction: outbound
tls: { [-]
cipher: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
client: { [-]
ja3: c12f54a3f91dc7bafd92cb59fe009a35
}
curve: x25519
established: true
resumed: false
server: { [-]
ja3s: ec74a5c51106f0419184d0dd08fb05bc
}
version: 1.2
version_protocol: tls
}
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 15/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Cobalt Strike C2:
IP Address: 5.188.86.237
Connection to the following URIs was observed:
Cobalt Strike Server Config:
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 16/28
10/6/24, 12:30 AM {
SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
"beacontype": [
"HTTPS"
],
"sleeptime": 120000,
"jitter": 12,
"maxgetsize": 1398924,
"spawnto": "AAAAAAAAAAAAAAAAAAAAAA==",
"license_id": 1580103824,
"cfg_caution": false,
"kill_date": null,
"server": {
"hostname": "5.188.86.237",
"port": 443,
"publickey": "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBi
},
"host_header": "",
"useragent_header": null,
"http-get": {
"uri": "/functionalStatus/2JYbAmfY5gYNj7UrgAte5
"verb": "GET",
"client": {
"headers": null,
"metadata": null
},
"server": {
"output": [
"print",
"append 8 characters",
"append 8 characters",
"append 10 characters",
"append 6 characters",
"append 11 characters",
"append 33 characters",
"append 69 characters",
"append 55 characters",
"append 67 characters",
"append 27 characters",
"append 15 characters",
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 17/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
"append 25 characters",
"append 32 characters",
"append 72 characters",
"prepend 16 characters",
"prepend 17 characters",
"prepend 11 characters",
"prepend 31 characters",
"prepend 80 characters",
"prepend 60 characters",
"prepend 54 characters",
"prepend 69 characters",
"prepend 38 characters",
"prepend 8 characters",
"base64url"
]
}
},
"http-post": {
"uri": "/rest/2/meetings2JYbAmfY5gYNj7UrgAte5p1
"verb": "GET",
"client": {
"headers": null,
"id": null,
"output": null
}
},
"tcp_frame_header": "AAQAAAAAAAAAAAAAAAAAAAAAAAAAAA
"crypto_scheme": 0,
"proxy": {
"type": null,
"username": null,
"password": null,
"behavior": "Use IE settings"
},
"http_post_chunk": 96,
"uses_cookies": false,
"post-ex": {
"spawnto_x86": "%windir%\\syswow64\\auditpol.ex
"spawnto_x64": "%windir%\\sysnative\\auditpol.e
},
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 18/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
"process-inject": {
"allocator": "NtMapViewOfSection",
"execute": [
"CreateThread 'ntdll.dll!RtlUserThreadStart
"NtQueueApcThread-s",
"SetThreadContext",
"CreateRemoteThread",
"CreateThread 'kernel32.dll!LoadLibraryA'",
"RtlCreateUserThread"
],
"min_alloc": 40263,
"startrwx": true,
"stub": "IiuPJ9vfuo3dVZ7son6mSA==",
"transform-x86": [
"prepend '\\x90\\x90\\x90\\x90\\x90\\x90\\x
],
"transform-x64": [
"prepend '\\x90\\x90\\x90\\x90\\x90\\x90\\x
],
"userwx": false
},
"dns-beacon": {
"dns_idle": null,
"dns_sleep": null,
"maxdns": null,
"beacon": null,
"get_A": null,
"get_AAAA": null,
"get_TXT": null,
"put_metadata": null,
"put_output": null
},
"pipename": null,
"smb_frame_header": "AAQAAAAAAAAAAAAAAAAAAAAAAAAAAA
"stage": {
"cleanup": true
},
"ssh": {
"hostname": null,
"port": null,
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 19/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
"username": null,
"password": null,
"privatekey": null
}
}
Impact
The BlueSky ransomware binary named vmware.exe was dropped
on the beachhead, which upon execution, resulted in network wide
ransomware. This was accomplished using SMB with the
ransomware connecting to host over port 445 to encrypt files.
The files were renamed with the file extension .bluesky and a
ransom note file named # DECRYPT FILES BLUESKY #.txt was
dropped on the host and opened to reveal the ransom note.
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 20/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
On the beachhead server, the time of encryption was visible as the
MSSQL service stopped functioning after execution of vmware.exe :
The whole intrusion after initial access lasted only around 30
minutes with limited discovery and no exfiltration observed.
Timeline
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 21/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Diamond Model
https://thedfirreport.com/2023/12/04/sql-brute-force-leads-to-bluesky-ransomware/ 22/28
10/6/24, 12:30 AM SQL Brute Force Leads to BlueSky Ransomware – The DFIR Report
Indicators
Atomic
hxxp://0x53611451/win/clocal
hxxp://qlqd5zqefmkcr34a[.]onion[.]sh/win/checking[.]hta
hxxps://asq[.]d6shiiwz[.]pw/win/hssl/d6[.]hta
hxxp://83[.]97[.]20[.]81/win/checking[.]hta
hxxp://83[.]97[.]20[.]81/win/update[.]hta
hxxps://asd[.]s7610rir[.]pw/win/checking[.]hta
hxxps://asq[.]r77vh0[.]pw/win/hssl/r7[.]hta
hxxp://asq[.]r77vh0[.]pw/win/checking[.]hta
hxxp://5[.]188[.]86[.]237/vmware[.]exe
    """

    print("**** Creating Crew ****")
    custom_crew = CustomCrew(var1)
    print("**** RUNNING CREW ****")
    result = custom_crew.run()
    print("\n\n########################")
    print("## Here is you custom crew run result:")
    print("########################\n")
    print(result)
