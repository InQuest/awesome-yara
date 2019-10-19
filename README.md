<p align="center">
  <img height="128" src="./awesome-yara.png"  alt="Awesome YARA" title="Awesome YARA">
</p>

<h1 align="center">Awesome YARA</h1>

A curated list of awesome YARA rules, tools, and resources. Inspired by [awesome-python](https://github.com/vinta/awesome-python) and [awesome-php](https://github.com/ziadoz/awesome-php).

> YARA is an ancronym for: YARA: Another Recursive Ancronym, or Yet Another Ridiculous Acronym. Pick your choice.
>
> -- *[Victor M. Alvarez (@plusvic)](https://twitter.com/plusvic/status/778983467627479040)*

[YARA](https://virustotal.github.io/yara/), the "pattern matching swiss knife for malware researchers (and everyone else)" is developed by [@plusvic](https://github.com/plusvic/) and [@VirusTotal](https://github.com/VirusTotal). View it on [GitHub](https://github.com/virustotal/yara).

### Contents

* [Rules](#rules)
* [Tools](#tools)
* [Services](#services)
* [Syntax Highlighters](#syntax-highlighters)
* [People](#people)
* [Related Awesome Lists](#related-awesome-lists)
* [Contributing](#contributing)
* [Just for Fun](http://yaramate.com)

### Legend

* :eyes: - Actively maintained, a repository worth watching.
* :gem: - Novel, interesting, educational, or otherwise stand-out content.
* :sparkles: - Recently released, shiny new toys.
* :trophy: - The biggest collection award, awarded to a single repo.

## Rules

* [AlienVault Labs Rules](https://github.com/AlienVault-Labs/AlienVaultLabs/tree/master/malware_analysis)
    - Collection of tools, signatures, and rules from the researchers at [AlienVault Labs](https://www.alienvault.com/blogs/labs-research). Search the repo for .yar and .yara extensions to find about two dozen rules ranging from APT detection to generic sandbox / VM detection. Last updated in January of 2016.
* [Apple OSX](https://gist.github.com/pedramamini/c586a151a978f971b70412ca4485c491)
    - Apple has ~40 YARA signatures for detecting malware on OSX. The file, XProtect.yara, is available locally at /System/Library/CoreServices/XProtect.bundle/Contents/Resources/.
* [bamfdetect rules](https://github.com/bwall/bamfdetect/tree/master/BAMF_Detect/modules/yara)
    - Custom rules from Brian Wallace used for bamfdetect, along with some rules from other sources.
* [BinaryAlert YARA Rules](https://github.com/airbnb/binaryalert/tree/master/rules/public)
    - A couple dozen rules written and released by AirBnB as part of their BinaryAlert tool (see next section). Detection for hack tools, malware, and ransomware across Linux, Window, and OS X. This is a new and active project.
* [Burp YARA Rules](https://github.com/codewatchorg/Burp-Yara-Rules)
    - Collection of YARA rules intended to be used with the Burp Proxy through the Yara-Scanner extension. These rules focus mostly on non-exe malware typically delivered over HTTP including HTML, Java, Flash, Office, PDF, etc. Last updated in June of 2016.
* [BinSequencer](https://github.com/karttoon/binsequencer)
    - Find a common pattern of bytes within a set of samples and generate a YARA rule from the identified pattern.
* [Brian Carter Rules](https://github.com/carterb/yararules)
    - Collection of personal rules written by Brian Carter, mostly designed for VirusTotal hunting.
* [CAPE Rules](https://github.com/ctxis/CAPE/tree/master/data/yara/CAPE) :eyes:
    - Rules from various authors bundled with the Config And Payload Extraction Cuckoo Sandbox extension (see next section).
* [CDI Rules](https://github.com/CyberDefenses/CDI_yara)
    - Collection of YARA rules released by [CyberDefenses](https://cyberdefenses.com/blog/) for public use. Built from information in intelligence profiles, dossiers and file work.
* [Citizen Lab Malware Signatures](https://github.com/citizenlab/malware-signatures)
    - YARA signatures developed by Citizen Lab. Dozens of signatures covering a variety of malware families. The also inclde a syntax file for Vim. Last update was in November of 2016.
* [ConventionEngine Rules](https://github.com/stvemillertime/ConventionEngine)
    - A collection of Yara rules looking for PEs with PDB paths that have unique, unusual, or overtly malicious-looking keywords, terms, or other features.
* [Deadbits Rules](https://github.com/deadbits/yara-rules) :eyes:
    - A collection of YARA rules made public by [Adam Swanda](https://www.deadbits.org/), Splunk's Principal Threat Intel. Analyst, from his own recent malware research.
* [Didier Stevens Rules](https://github.com/DidierStevens/DidierStevensSuite) :gem:
    - Collection of rules from Didier Stevens, author of a suite of tools for inspecting OLE/RTF/PDF. Didier's rules are worth scrutinizing and are generally written purposed towards hunting. New rules are frequently announced through the [NVISO Labs Blog](https://blog.nviso.be/).
* [ESET IOCs](https://github.com/eset/malware-ioc/) :eyes:
    - Collection of YARA and Snort rules from IOCs collected by ESET researchers. There's about a dozen YARA Rules to glean from in this repo, search for file extension .yar. This repository is seemingly updated on a roughly monthly interval. New IOCs are often mentioned on the [ESET WeLiveSecurity Blog](https://www.welivesecurity.com/).
* [Fidelis Rules](https://github.com/fideliscyber/indicators/tree/master/yararules)
    - You can find a half dozen YARA rules in Fidelis Cyber's IOC repository. They update this repository on a roughly quarterly interval. Complete blog content is also available in this repository.
* [Florian Roth Rules](https://github.com/Neo23x0/signature-base/tree/master/yara) :eyes: :gem:
    - Florian Roth's signature base is a frequently updated collection of IOCs and YARA rules that cover a wide range of threats. There are dozens of rules which are actively maintained. Watch the repository to see rules evolve over time to address false potives / negatives.
* [Florian Roth's IDDQD Rule](https://gist.github.com/Neo23x0/f1bb645a4f715cb499150c5a14d82b44)
    - A proof-of-concept rule that shows how easy it actually is to detect red teamer and threat group tools and code. 
* [FSF Rules](https://github.com/EmersonElectricCo/fsf/tree/master/fsf-server/yara)
    - Mostly filetype detection rules, from the EmersonElectricCo FSF project (see next section).
* [GoDaddy ProcFilter Rules](https://github.com/godaddy/yara-rules)
    - A couple dozen rules written and released by GoDaddy for use with ProcFilter (see next section). Example rules include detection for packers, mimikatz, and specific malware.
* [h3x2b Rules](https://github.com/h3x2b/yara-rules) :gem:
    - Collection of signatures from h3x2b which stand out in that they are generic and can be used to assist in reverse engineering. There are YARA rules for identifying crypto routines, highly entropic sections (certificate discovery for example), discovering injection / hooking functionality, and more.
* [Icewater Rules](https://github.com/SupportIntelligence/Icewater)
    - Repository of automatically generated YARA rules from Icewater.io. This repository is updated rapidly with newly generated signatures that mostly match on file size range and partial content hashes.
* [InQuest Rules](https://github.com/InQuest/yara-rules) :eyes:
    - YARA rules published by InQuest researchers mostly geared towards threat hunting on Virus Total. Rules are updated as new samples are collected and novel pivots are discovered. The [InQuest Blog](http://blog.inquest.net) will often discuss new findings.
* [kevthehermit Rules](https://github.com/kevthehermit/YaraRules)
    - Dozens of rules from the personal collection of Kevin Breen. This repository hasn't been updated since February of 2016.
* [Koodous Community Rules](https://koodous.com/rulesets)
    - Community-contributed rules for Android APK malware.
* [lw-yara](https://github.com/Hestat/lw-yara)
    - Ruleset for scanning Linux servers for shells, spamming, phishing and other webserver baddies.
* [NCC Group Rules](https://github.com/nccgroup/Cyber-Defence/tree/master/Signatures/yara) :eyes:
    - A handful of YARA rules released by NCC Group's Cyber Defence team.
* [Malice.IO YARA Plugin Rules](https://github.com/malice-plugins/yara/tree/master/rules) :eyes:
    - Collection of topical from a variety of sources for the YARA component of the Malice.IO framework.
* [Malpedia Auto Generated Rules](https://malpedia.caad.fkie.fraunhofer.de/api/get/yara/auto/zip) :sparkles:
    - A zip file that contains all automatically generated, code-based rules created using Malpedia's YARA-Signator
* [McAfee Advanced Threat Research IOCs](https://github.com/advanced-threat-research/IOCs)
    - IOCs, including YARA rules, to accompany McAfee ATR's blog and other public posts.
* [mikesxrs YARA Rules Collection](https://github.com/mikesxrs/Open-Source-YARA-rules) :eyes: :trophy:
    - Large collection of open source rules aggregated from a variety of sources, including blogs and other more ephemeral sources. Over 100 categories, 1500 files, 4000 rules, and 20Mb. If you're going to pull down a single repo to play with, this is the one.
* [MrThreat Rules](https://github.com/MrThreat/yararules)
    - Pubic repository of yara rules mainly used for osint and threat/counter intelligence.
* [Patrick Olsen Rules](https://github.com/prolsen/YaraRules) :gem:
    - Small collection of rules with a wide footprint for variety in detection. RATs, documents, PCAPs, executables, in-memory, point-of-sale malware, and more. Unfortunately this repository hasn't seen an update since late 2014.
* [QuickSand Lite Rules](https://github.com/tylabs/quicksand_lite)
    - This repo contains a C framework and standalone tool for malware analysis, along with several useful YARA rules developed for use with the project.
* [rastrea2r](https://github.com/rastrea2r/rastrea2r)
    - Triage suspect systems and hunt for Indicators of Compromise (IOCs) across thousands of endpoints in minutes.
* [SpiderLabs Rules](https://github.com/SpiderLabs/malware-analysis/tree/master/Yara)
    - Repository of tools and scripts related to malware analysis from the researchers at SpiderLabs. There's only three YARA rules here and the last update was back in 2015, but worth exploring.
* [Tenable Rules](https://github.com/tenable/yara-rules)
    - Small collection from Tenable Network Security.
* [TjadaNel Rules](https://github.com/tjadanel/yara_repo)
    - Small collection of malware rules.
* [VectraThreatLab Rules](https://github.com/VectraThreatLab/reyara)
    - YARA rules for identifying anti-RE malware techniques.
* [x64dbg Signatures](https://github.com/x64dbg/yarasigs) :gem:
    - Collection of interesting packer, compiler, and crypto identification signatures.
* [YARA-FORENSICS](https://github.com/Xumeiquer/yara-forensics)
    - Collection of file type identfiying rules.
* [yara4pentesters](https://github.com/DiabloHorn/yara4pentesters)
    - Rules to identify files containing juicy information like usernames, passwords etc.
* [YaraRules Project Official Repo](https://github.com/Yara-Rules/rules) :eyes:
    - Large collection of rules constantly updated by the community.
* [Yara-Unprotect](https://github.com/fr0gger/Yara-Unprotect)
    - Rules created for the Unprotect Project for detecting malware evasion techniques.

## Tools

* [AirBnB BinaryAlert](https://github.com/airbnb/binaryalert)
    - Open-source serverless AWS pipeline where any file uploaded to an S3 bucket is immediately scanned with a configurable set of YARA rules.
* [androguard](https://github.com/Koodous/androguard-yara)
    - YARA module that integrates APK analysis.
* [bamfdetect](https://github.com/bwall/bamfdetect)
    - Identifies and extracts information from bots and other malware.
* [base64_substring](https://github.com/DissectMalware/base64_substring)
    - Generate YARA rules to match terms against base64-encoded data.
* [CAPE: Config And Payload Extraction](https://github.com/ctxis/CAPE) :eyes:
    - Extension of Cuckoo specifically designed to extract payloads and configuration from malware. CAPE can detect a number of malware techniques or behaviours, as well as specific malware families, from its initial run on a sample. This detection then triggers a second run with a specific package, in order to extract the malware payload and possibly its configuration, for further analysis.
* [CrowdStrike Feed Management System](https://github.com/CrowdStrike/CrowdFMS)
    - Framework for automating collection and processing of samples from VirusTotal, and executing commands based on YARA rule matches.
* [CSE-CST AssemblyLine](https://bitbucket.org/cse-assemblyline/alsvc_yara)
    - The Canadian Communications Security Establishment (CSE) open sourced [AssemblyLine](https://www.cse-cst.gc.ca/en/assemblyline), a platform for analyzing malicious files. The component linked here provides an interface to YARA.
* [dnYara](https://github.com/airbus-cert/dnYara)
    - A multi-platform .NET wrapper library for the native YARA library.
* [ELAT](https://github.com/reed1713/ELAT)
    - Event Log Analysis Tool that creates/uses YARA rules for Windows event log analysis.
* [Emerson File Scanning Framework (FSF)](https://github.com/EmersonElectricCo/fsf)
    - Modular, recursive file scanning solution.
* [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) and [FindYara](https://github.com/OALabs/FindYara)
    - IDA pro plugins to scan your binary with YARA rules to find crypto constants (and more).
* [Fnord](https://github.com/Neo23x0/Fnord)
    - Pattern extractor for obfuscated code.
* [generic-parser](https://github.com/uppusaikiran/generic-parser)
    - Parser with YARA support, to extract meta information, perform static analysis and detect macros within files.
* [GoDaddy ProcFilter](https://github.com/godaddy/procfilter) :gem:
    - ProcFilter is a process filtering system for Windows with built-in YARA integration. YARA rules can be instrumented with custom meta tags that tailor its response to rule matches. It runs as a Windows service and is integrated with Microsoft's ETW API, making results viewable in the Windows Event Log. Installation, activation, and removal can be done dynamically and does not require a reboot.
* [go-yara](https://github.com/hillu/go-yara)
    - Go bindings for YARA.
* [Hyara](https://github.com/hy00un/Hyara)
    - IDAPro plugin providing easy creation of YARA rules for ASCII & hex strings between a given start and end address.
* [IDA_scripts](https://github.com/swackhamer/IDA_scripts)
    - IDA Python scripts for generating YARA sigs from executable opcodes (.NET included).
* [ida_yara](https://github.com/alexander-hanel/ida_yara)
    - Scan data within an IDB using YARA.
* [ida-yara-processor](https://github.com/bnbdr/ida-yara-processor)
    - IDA processor for compiled YARA rules.
* [InQuest ThreatKB](https://github.com/InQuest/ThreatKB)
    - Knowledge base workflow management for YARA rules and C2 artifacts (IP, DNS, SSL).
* [iocextract](https://github.com/InQuest/python-iocextract)
    - Advanced Indicator of Compromise (IOC) extractor, with YARA rule extraction.
* [Invoke-Yara](https://github.com/secabstraction/Yara)
    - Powershell scripts to run YARA on remote machines.
* [KLara](https://github.com/KasperskyLab/klara)
    - Distributed system written in Python, allows researchers to scan one or more YARA rules over collections with samples.
* [Laika BOSS](https://github.com/lmco/laikaboss)
    - Object scanner and intrusion detection system that strives to achieve the following goals: Scalable, Flexible, Verbose.
    - [Whitepaper](https://lockheedmartin.com/content/dam/lockheed/data/isgs/documents/LaikaBOSS%20Whitepaper.pdf)
* [Malice](https://malice.io/)
    - Open source VirusTotal alternative, with YARA support.
* [malscan](https://github.com/usualsuspect/malscan)
    - Scan process memory for YARA matches and execute Python scripts if a match is found.
* [MISP Threat Sharing](https://www.github.com/MISP/MISP)
    - Threat intelligence platform including indicators, threat intelligence, malware samples and binaries. Includes support for sharing, generating, and validating YARA signatures.
* [MITRE MultiScanner](https://github.com/mitre/multiscanner)
    - File analysis framework that assists the user in evaluating a set of files by automatically running a suite of tools for the user and aggregating the output.
* [mkYARA](https://github.com/fox-it/mkYARA)
    - Generate YARA rules based on binary code.
* [mquery](https://github.com/CERT-Polska/mquery)
    - Web frontend for running blazingly fast YARA queries on large datasets.
* Nextron Systems OSS and Commercial Tools (Florian Roth: @Neo23x0)
    - [Loki](https://github.com/Neo23x0/Loki) IOC and YARA rule scanner implemented in Python. Open source and free.
    - [SPARK Core](https://www.nextron-systems.com/spark-core/) IOC and YARA rule scanner implemented in Go. Closed source, free, but registration required.
* [node-yara](https://github.com/stephenwvickers/node-yara)
    - YARA support for Node.js.
* [OCYara](https://github.com/bandrel/OCyara)
    - Performs OCR on image files and scans them for matches to YARA rules.
* [PasteHunter](https://github.com/kevthehermit/PasteHunter)
    - Scan pastebin.com with YARA rules.
* [plast](https://github.com/sk4la/plast)
    - Threat hunting tool for detecting and processing IOCs using YARA under the hood.
* [plyara](https://github.com/plyara/plyara)
    - Parse YARA rules with Python.
* [Polichombr](https://github.com/ANSSI-FR/polichombr)
    - Collaborative malware analysis framework with YARA rule matching and other features.
* [VirusTotalTools](https://github.com/silascutler/VirusTotalTools)
    - Tools for checking samples against Virus Total, including VT_RuleMGR, for managing threat hunting YARA rules.
* [QuickSand.io](http://quicksand.io/)
    - Compact C framework to analyze suspected malware documents. Also includes a web interface and online analysis.
* [shotgunyara](https://github.com/darienhuss/shotgunyara)
    - Given a string, create 255 xor encoded versions of that string as a YARA rule.
* [spyre](https://github.com/DCSO/spyre)
    - Simple, self-contained YARA-based file IOC scanner.
* [static_file_analysis](https://github.com/lprat/static_file_analysis)
    - Analyze deeply embedded files (doc, pdf, exe, ...) with clamscan and YARA.
* [stoQ](https://github.com/PUNCH-Cyber/stoq)
    - Modular and highly customizable framework for the creation of data sets from multiple disparate data sources.
* [Strelka](https://github.com/target/strelka)
    - Detection-Oriented File Analysis System built on Python3, ZeroMQ, and YARA, primarily used for threat detection/hunting and intelligence gathering.
* [SwishDbgExt](https://github.com/comaeio/SwishDbgExt)
    - Microsoft WinDbg extension which includes the ability to use YARA rules to hunt processes in memory.
* [ThreatIngestor](https://github.com/InQuest/ThreatIngestor/)
    - Automatically extract and aggregate IOCs including YARA rules from many sources.
* [Vxsig](https://github.com/google/vxsig)
    - Automatically generate AV byte signatures from sets of similar binaries.
* [yabin](https://github.com/AlienVault-OTX/yabin)
    - Creates YARA signatures from executable code within malware.
* [yaml2yara](https://github.com/nccgroup/yaml2yara)
    - Generate bulk YARA rules from YAML input.
* [yara-endpoint](https://github.com/Yara-Rules/yara-endpoint)
    -  Tool useful for incident response as well as anti-malware enpoint based on YARA signatures.
* [Yara Finder](https://github.com/uppusaikiran/yara-finder)
    - Web API and docker image for scanning files against YARA rules, built on @tylerha97's yara_scan.
* [YaraGenerator](https://github.com/Xen0ph0n/YaraGenerator)
    - Quick, simple, and effective yara rule creation to isolate malware families and other malicious objects of interest.
* [YaraGen](https://github.com/mrexodia/YaraGen) and [yara_fn](https://github.com/williballenthin/idawilli/tree/master/scripts/yara_fn)
    - Plugins for x64dbg and IDAPython, respectively, that generate YARA rules from function blocks.
* [YaraGuardian](https://github.com/PUNCH-Cyber/YaraGuardian)
    - Django web inerface for managing YARA rules.
* [yaraMail](https://github.com/kevthehermit/yaraMail)
    - YARA scanner for IMAP feeds and saved streams.
* [Yara Malware Quick menu scanner](https://github.com/techbliss/Yara_Mailware_Quick_menu_scanner)
    - Adds the awsome YARA pattern scanner to Windows right click menus.
* [YaraManager](https://github.com/kevthehermit/YaraManager)
    - Web based manager for YARA rules.
* [yarAnalyzer](https://github.com/Neo23x0/yarAnalyzer)
    - YARA rule set coverage analyzer.
* [yara-parser](https://github.com/Northern-Lights/yara-parser)
    - Tools for parsing rulesets using the exact grammar as YARA. Written in Go.
* [yaraPCAP](https://github.com/kevthehermit/YaraPcap)
    - YARA scanner For IMAP feeds and saved streams.
* [yara-procdump-python](https://github.com/google/yara-procdump-python)
    - Python extension to wrap the YARA process memory access API.
* [yara-signator](https://github.com/fxb-cocacoding/yara-signator) :sparkles:
    - Automatic YARA rule generation for Malpedia
* [Yara Python ICAP Server](https://github.com/RamadhanAmizudin/python-icap-yara)
    - ICAP server with YARA scanner.
* [yarasafe](https://github.com/lucamassarelli/yarasafe)
    - Automatic generation of function signature using machine learning.
* [yara_scan](https://github.com/tylerha97/yara_scan)
    - Extract zips, pull macros out of documents, and scan everything against YARA rules.
* [Yara-Scanner](https://github.com/PolitoInc/Yara-Scanner)
    - Python-based extension that integrates a YARA scanner into Burp Suite.
* [yarascanner](https://github.com/jheise/yarascanner)
    - Golang-based web service to scan files with YARA rules.
* [yara_tools](https://github.com/matonis/yara_tools)
    - Python bindings to author YARA rules using natural Python conventions.
* [Yara-Validator](https://github.com/CIRCL/yara-validator)
    - Validates YARA rules and tries to repair the broken ones.
* [yaraVT](https://github.com/deadbits/yaraVT)
    - Scan files with Yara and send rule matches to VirusTotal reports as comments.
* [yara_zip_module](https://github.com/stoerchl/yara_zip_module)
    - Search for strings inside a zip file.
* [yarGen](https://github.com/Neo23x0/yarGen)
    - YARA rule generator for finding related samples and hunting.
* [YaYaGen](https://github.com/jimmy-sonny/YaYaGen)
    - YARA rule generator for Android malware.
* [Yeti](https://github.com/yeti-platform/yeti)
    - Platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository.
* [yextend](https://github.com/BayshoreNetworks/yextend)
    - YARA integrated software to handle archive file data.
* [yaraZeekAlert](https://github.com/SCILabsMX/yaraZeekAlert) :sparkles:
    - Scans files with YARA rules and send email alerts which include network context of the file transfer and attaches the suspicious file if it is less than 10 MB.

## Services

* [Hybrid Analysis YARA Search](https://www.hybrid-analysis.com/yara-search)
    - YARA search / hunting from CrowdStrike / Hybrid Analysis, powered by Falcon MalQuery.
* [InQuest Labs](https://labs.inquest.net) :sparkles:
    -  See the YARA section for helper routines to convert regular expressions to match on base64 encoded strings, conver strings to sequences of uint() lookups, and more.
* [Koodous](https://koodous.com/)
    - Collaborative platform for APK analysis, with community YARA rule repository and large APK sample dataset.
* [MalShare](https://malshare.com/)
    - Free malware repository providing researchers access to samples, malicous feeds, and YARA results.
* [MalwareConfig](https://malwareconfig.com/)
    - Extract IOCs from Remote Access Trojans.
* [YaraEditor (Web)](https://www.adlice.com/download/yaraeditorweb/)
    - All-in-one website to create and manage YARA rules.
* [YaraRules Analyzer](https://analysis.yararules.com/)
    - Upload and run files against rulesets from the YaraRules Project.
* [Yara Share](https://yara.adlice.com/)
    - Free repository and online community for users to upload and share Yara rules.

## Syntax Highlighters

* Atom: [language-yara](https://github.com/blacktop/language-yara)
* GTK-based editors, like gedit and xed: [GtkSourceView-YARA](https://github.com/wesinator/GtkSourceView-YARA)
* Sublime Text: [YaraSyntax](https://github.com/nyx0/YaraSyntax/)
* Vim: [vim-yara](https://github.com/yaunj/vim-yara)
* Visual Studio Code: [textmate-yara](https://github.com/infosec-intern/textmate-yara)

## People

We're aggregating the Twitter handles for anyone involved with the projects on this page into a single list: [awesome-yara Twitter list](https://twitter.com/InQuest/lists/awesome-yara). Do let us know if anyone is missing.

## Related Awesome Lists

* [Crawler](https://github.com/BruceDone/awesome-crawler)
* [CVE PoC](https://github.com/qazbnm456/awesome-cve-poc)
* [Forensics](https://github.com/Cugu/awesome-forensics)
* [Hacking](https://github.com/carpedm20/awesome-hacking)
* [HackwithGithub](https://github.com/Hack-with-Github/Awesome-Hacking)
* [Honeypots](https://github.com/paralax/awesome-honeypots)
* [Incident-Response](https://github.com/meirwah/awesome-incident-response)
* [Infosec](https://github.com/onlurking/awesome-infosec)
* [IOCs](https://github.com/sroberts/awesome-iocs)
* [Malware Analysis](https://github.com/rshipp/awesome-malware-analysis)
* [ML for Cyber Security](https://github.com/jivoi/awesome-ml-for-cybersecurity)
* [OSINT](https://github.com/jivoi/awesome-osint)
* [PCAP Tools](https://github.com/caesar0301/awesome-pcaptools)
* [Pentesting](https://github.com/enaqx/awesome-pentest)
* [Reversing](https://github.com/fdivrp/awesome-reversing)
* [Security](https://github.com/sbilly/awesome-security)
* [Static Analysis](https://github.com/mre/awesome-static-analysis)
* [Threat Detection](https://github.com/0x4D31/awesome-threat-detection)
* [Threat Intelligence](https://github.com/hslatman/awesome-threat-intelligence)

## Contributing

This list is maintained by [InQuest](https://inquest.net/). Feel free to let us
know about anything we're missing!

See [CONTRIBUTING.md](CONTRIBUTING.md).
