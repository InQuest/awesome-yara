# Awesome YARA [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)

A curated list of awesome YARA rules, tools, and resources. Inspired by [awesome-python](https://github.com/vinta/awesome-python) and [awesome-php](https://github.com/ziadoz/awesome-php).

> YARA is an ancronym for: YARA: Another Recursive Ancronym, or Yet Another Ridiculous Acronym. Pick your choice.
>
> -- *[Victor M. Alvarez (@plusvic)](https://twitter.com/plusvic/status/778983467627479040)*

[YARA](https://virustotal.github.io/yara/), the "pattern matching swiss knife for malware researchers (and everyone else)" is developed by [@plusvic](https://github.com/plusvic/) and [@VirusTotal](https://github.com/VirusTotal). View it on [GitHub](https://github.com/virustotal/yara).

### Contents

- [Awesome YARA](#awesome-yara-)
    - [Rules](#rules)
    - [Tools](#tools)
    - [Services](#services)
    - [People](#people)
    - [Related Awesome Lists](#related-awesome-lists)
    - [Contributing](#contributing)

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
* [BinaryAlert YARA Rules](https://github.com/airbnb/binaryalert/tree/master/rules/public) :eyes: :sparkles:
    - A couple dozen rules written and released by AirBnB as part of their BinaryAlert tool (see next section). Detection for hack tools, malware, and ransomware across Linux, Window, and OS X. This is a new and active project.
* [Burp YARA Rules](https://github.com/codewatchorg/Burp-Yara-Rules)
    - Collection of YARA rules intended to be used with the Burp Proxy through the Yara-Scanner extension. These rules focus mostly on non-exe malware typically delivered over HTTP including HTML, Java, Flash, Office, PDF, etc. Last updated in June of 2016.
* [Brian Carter Rules](https://github.com/carterb/yararules) :sparkles:
    - Collection of personal rules written by Brian Carter, mostly designed for VirusTotal hunting.
* [CAPE Rules](https://github.com/ctxis/CAPE/tree/master/data/yara/CAPE) :eyes:
    - Rules from various authors bundled with the Config And Payload Extraction Cuckoo Sandbox extension (see next section).
* [CDI Rules](https://github.com/CyberDefenses/CDI_yara) :sparkles:
    - Collection of YARA rules released by [CyberDefenses](https://cyberdefenses.com/blog/) for public use. Built from information in intelligence profiles, dossiers and file work.
* [Citizen Lab Malware Signatures](https://github.com/citizenlab/malware-signatures)
    - YARA signatures developed by Citizen Lab. Dozens of signatures covering a variety of malware families. The also inclde a syntax file for Vim. Last update was in November of 2016.
* [Didier Stevens Rules](https://github.com/DidierStevens/DidierStevensSuite) :gem:
    - Collection of rules from Didier Stevens, author of a suite of tools for inspecting OLE/RTF/PDF. Didier's rules are worth scrutinizing and are generally written purposed towards hunting. New rules are frequently announced through the [NVISO Labs Blog](https://blog.nviso.be/).
* [ESET IOCs](https://github.com/eset/malware-ioc/) :eyes:
    - Collection of YARA and Snort rules from IOCs collected by ESET researchers. There's about a dozen YARA Rules to glean from in this repo, search for file extension .yar. This repository is seemingly updated on a roughly monthly interval. New IOCs are often mentioned on the [ESET WeLiveSecurity Blog](https://www.welivesecurity.com/).
* [Fidelis Rules](https://github.com/fideliscyber/indicators/tree/master/yararules)
    - You can find a half dozen YARA rules in Fidelis Cyber's IOC repository. They update this repository on a roughly quarterly interval. Complete blog content is also available in this repository.
* [Florian Roth Rules](https://github.com/Neo23x0/signature-base/tree/master/yara) :eyes: :gem:
    - Florian Roth's signature base is a frequently updated collection of IOCs and YARA rules that cover a wide range of threats. There are dozens of rules which are actively maintained. Watch the repository to see rules evolve over time to address false potives / negatives.
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
* [NCC Group Rules](https://github.com/nccgroup/Cyber-Defence/tree/master/Signatures/yara) :eyes:
    - A handful of YARA rules released by NCC Group's Cyber Defence team.
* [Malice.IO YARA Plugin Rules](https://github.com/malice-plugins/yara/tree/master/rules) :eyes:
    - Collection of topical from a variety of sources for the YARA component of the Malice.IO framework.
* [mikesxrs YARA Rules Collection](https://github.com/mikesxrs/Open-Source-YARA-rules) :eyes: :trophy:
    - Large collection of open source rules aggregated from a variety of sources, including blogs and other more ephemeral sources. Over 100 categories, 1500 files, 4000 rules, and 20Mb. If you're going to pull down a single repo to play with, this is the one.
* [MrThreat Rules](https://github.com/MrThreat/yararules)
    - Pubic repository of yara rules mainly used for osint and threat/counter intelligence.
* [Patrick Olsen Rules](https://github.com/prolsen/YaraRules) :gem:
    - Small collection of rules with a wide footprint for variety in detection. RATs, documents, PCAPs, executables, in-memory, point-of-sale malware, and more. Unfortunately this repository hasn't seen an update since late 2014.

* [QuickSand Lite Rules](https://github.com/tylabs/quicksand_lite)
    - This repo contains a C framework and standalone tool for malware analysis, along with several useful YARA rules developed for use with the project.
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

## Tools

* [AirBnB BinaryAlert](https://github.com/airbnb/binaryalert)
    - Open-source serverless AWS pipeline where any file uploaded to an S3 bucket is immediately scanned with a configurable set of YARA rules.
* [bamfdetect](https://github.com/bwall/bamfdetect)
    - Identifies and extracts information from bots and other malware.
* [CAPE: Config And Payload Extraction](https://github.com/ctxis/CAPE) :eyes:
    - Extension of Cuckoo specifically designed to extract payloads and configuration from malware. CAPE can detect a number of malware techniques or behaviours, as well as specific malware families, from its initial run on a sample. This detection then triggers a second run with a specific package, in order to extract the malware payload and possibly its configuration, for further analysis.
* [CrowdStrike Feed Management System](https://github.com/CrowdStrike/CrowdFMS)
    - Framework for automating collection and processing of samples from VirusTotal, and executing commands based on YARA rule matches.
* [CSE-CST AssemblyLine](https://bitbucket.org/cse-assemblyline/alsvc_yara) :sparkles:
    - The Canadian Communications Security Establishment (CSE) open sourced [AssemblyLine](https://www.cse-cst.gc.ca/en/assemblyline), a platform for analyzing malicious files. The component linked here provides an interface to YARA.
* [ELAT](https://github.com/reed1713/ELAT)
    - Event Log Analysis Tool that creates/uses YARA rules for Windows event log analysis.
* [Emerson File Scanning Framework (FSF)](https://github.com/EmersonElectricCo/fsf)
    - Modular, recursive file scanning solution.
* [findcrypt-yara](https://github.com/polymorf/findcrypt-yara) and [FindYara](https://github.com/OALabs/FindYara)
    - IDA pro plugins to scan your binary with YARA rules to find crypto constants (and more).
* [GoDaddy ProcFilter](https://github.com/godaddy/procfilter) :gem:
    - ProcFilter is a process filtering system for Windows with built-in YARA integration. YARA rules can be instrumented with custom meta tags that tailor its response to rule matches. It runs as a Windows service and is integrated with Microsoft's ETW API, making results viewable in the Windows Event Log. Installation, activation, and removal can be done dynamically and does not require a reboot.
* [go-yara](https://github.com/hillu/go-yara)
    - Go bindings for YARA.
* [IDA_scripts](https://github.com/swackhamer/IDA_scripts)
    - IDA Python scripts for generating YARA sigs from executable opcodes (.NET included).
* [InQuest ThreatKB](https://github.com/InQuest/ThreatKB)
    - Knowledge base workflow management for YARA rules and C2 artifacts (IP, DNS, SSL).
* [Invoke-Yara](https://github.com/secabstraction/Yara)
    - Powershell scripts to run YARA on remote machines.
* [KLara](https://github.com/KasperskyLab/klara)
    - Distributed system written in Python, allows researchers to scan one or more YARA rules over collections with samples.
* [Laika BOSS](https://github.com/lmco/laikaboss)
    - Object scanner and intrusion detection system that strives to achieve the following goals: Scalable, Flexible, Verbose.
    - [Whitepaper](https://lockheedmartin.com/content/dam/lockheed/data/isgs/documents/LaikaBOSS%20Whitepaper.pdf)
* [Loki](https://github.com/Neo23x0/Loki)
    - Simple IOC and YARA rule scanner.
* [Malice](https://malice.io/)
    - Open source VirusTotal alternative, with YARA support.
* [MISP Threat Sharing](https://www.github.com/MISP/MISP)
    - Threat intelligence platform including indicators, threat intelligence, malware samples and binaries. Includes support for sharing, generating, and validating YARA signatures.
* [MITRE MultiScanner](https://github.com/mitre/multiscanner)
    - File analysis framework that assists the user in evaluating a set of files by automatically running a suite of tools for the user and aggregating the output.
* [node-yara](https://github.com/stephenwvickers/node-yara)
    - YARA support for Node.js.
* [OCYara](https://github.com/bandrel/OCyara)
    - Performs OCR on image files and scans them for matches to YARA rules.
* [PasteHunter](https://github.com/kevthehermit/PasteHunter)
    - Scan pastebin.com with YARA rules.
* [QuickSand.io](http://quicksand.io/)
    - Compact C framework to analyze suspected malware documents. Also includes a web interface and online analysis.
* [stoQ](https://github.com/PUNCH-Cyber/stoq)
    - Modular and highly customizable framework for the creation of data sets from multiple disparate data sources.
* [SwishDbgExt](https://github.com/comaeio/SwishDbgExt)
    - Microsoft WinDbg extension which includes the ability to use YARA rules to hunt processes in memory.
* [yabin](https://github.com/AlienVault-OTX/yabin)
    - Creates YARA signatures from executable code within malware.
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
* [yaraPCAP](https://github.com/kevthehermit/YaraPcap)
    - YARA scanner For IMAP feeds and saved streams.
* [yara-procdump-python](https://github.com/google/yara-procdump-python)
    - Python extension to wrap the YARA process memory access API.
* [Yara Python ICAP Server](https://github.com/RamadhanAmizudin/python-icap-yara)
    - ICAP server with YARA scanner.
* [Yara-Scanner](https://github.com/PolitoInc/Yara-Scanner)
    - Python-based extension that integrates a YARA scanner into Burp Suite.
* [Yara-Validator](https://github.com/CIRCL/yara-validator)
    - Validates YARA rules and tries to repair the broken ones.
* [yaraVT](https://github.com/deadbits/yaraVT)
    - Scan files with Yara and send rule matches to VirusTotal reports as comments.
* [yarGen](https://github.com/Neo23x0/yarGen)
    - YARA rule generator for finding related samples and hunting.
* [Yeti](https://github.com/yeti-platform/yeti)
    - Platform meant to organize observables, indicators of compromise, TTPs, and knowledge on threats in a single, unified repository.
* [yextend](https://github.com/BayshoreNetworks/yextend)
    - YARA integrated software to handle archive file data.

### Services

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

See [CONTRIBUTING.md](CONTRIBUTING.md).
