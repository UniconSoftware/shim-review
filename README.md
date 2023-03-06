This repo is for review of requests for signing shim.  To create a request for review:

- clone this repo
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push that to github
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 on Linux, so asking
us to endorse anything else for signing is going to require some convincing on
your part.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Unicon GmbH
Ludwig-Erhard-Allee 26
76131 Karlsruhe
Tel.: +49 (721) 96451-0

*******************************************************************************
### What product or service is this for?
*******************************************************************************
We create a hardware-independent Linux distribution "eLux", for use with thin clients.

*******************************************************************************
### What's the justification that this really does need to be signed for the whole world to be able to boot it?
*******************************************************************************
We want to provide our customers additional security using the integrity checks secure boot does.

*******************************************************************************
### Why are you unable to reuse shim from another distro that is already signed?
*******************************************************************************
We ship our own kernel with an adjusted configuration and a few patches. To boot with secure boot enabled, shim needs to know the certificate of the CA used to sign the kernel image.

*******************************************************************************
### Who is the primary contact for security updates, etc.?
The security contacts need to be verified before the shim can be accepted. For subsequent requests, contact verification is only necessary if the security contacts or their PGP keys have changed since the last successful verification.

An authorized reviewer will initiate contact verification by sending each security contact a PGP-encrypted email containing random words.
You will be asked to post the contents of these mails in your `shim-review` issue to prove ownership of the email addresses and PGP keys.
*******************************************************************************
- Name: Jan Bungeroth
- Position: CTO
- Email address: jan.bungeroth@unicon.com
- PGP key fingerprint: 8A07 EECD A684 DCBC B41F  EDE5 686E 1189 8ACB 8132

The key is signed by two Debian Developers. Their keys can, naturally, be found in the Debian keyring.

*******************************************************************************
### Who is the secondary contact for security updates, etc.?
*******************************************************************************
- Name: Micha Lenk
- Position: Teamlead Software Engineering Linux
- Email address: micha.lenk@unicon.com
- PGP key fingerprint: DF97 30CE 093B E285 6EB7  4E8C EEE4 269E A71B FB37

Micha Lenk is a Debian Developers, he used his Debian key to sign this key here.

*******************************************************************************
### Were these binaries created from the 15.7 shim release tar?
Please create your shim binaries starting with the 15.7 shim release tar file: https://github.com/rhboot/shim/releases/download/15.7/shim-15.7.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/15.7 and contains the appropriate gnu-efi source.

*******************************************************************************
Yes. the git repository was based on shim-15.7.tar.bz2
(sha256: 87cdeb190e5c7fe441769dde11a1b507ed7328e70a178cd9858c7ac7065cfade)

*******************************************************************************
### URL for a repo that contains the exact code which was built to get this binary:
*******************************************************************************
https://github.com/UniconSoftware/shim

*******************************************************************************
### What patches are being applied and why:
*******************************************************************************
"Make sbat_var.S parse right with buggy gcc/binutils"
https://github.com/rhboot/shim/commit/657b2483ca6e9fcf2ad8ac7ee577ff546d24c3aa
Justification: Our old toolchain requires that fix.

"Enable the NX compatibility flag by default"
https://github.com/rhboot/shim/commit/7c7642530fab73facaf3eac233cfbce29e10b0ef
Justification: From other reviews it seemed this is mandatory now.

"CryptoPkg/BaseCryptLib: Fix buffer overflow issue in realloc wrapper"
https://github.com/rhboot/shim/commit/89972ae25c133df31290f394413c19ea903219ad
Justification: This looks like an important bugfix.

They are included in the repo mentioned in the previous question.

*******************************************************************************
### If shim is loading GRUB2 bootloader what exact implementation of Secureboot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
*******************************************************************************
We will use the sources as provided in Debian 11 ("bullseye")and use the result of dpkg-buildpackage.

We track the Debian repositories to learn about any important updates. 

We would prefer to follow Ubuntu 22.04 ("jammy") but it seems they haven't fixed the issues from last November (CVE-2022-2601 and CVE-2022-3775) yet.

*******************************************************************************
### If shim is loading GRUB2 bootloader and your previously released shim booted a version of grub affected by any of the CVEs in the July 2020 grub2 CVE list, the March 2021 grub2 CVE list, the June 7th 2022 grub2 CVE list, or the November 15th 2022 list, have fixes for all these CVEs been applied?

* CVE-2020-14372
* CVE-2020-25632
* CVE-2020-25647
* CVE-2020-27749
* CVE-2020-27779
* CVE-2021-20225
* CVE-2021-20233
* CVE-2020-10713
* CVE-2020-14308
* CVE-2020-14309
* CVE-2020-14310
* CVE-2020-14311
* CVE-2020-15705
* CVE-2021-3418 (if you are shipping the shim_lock module)

* CVE-2021-3695
* CVE-2021-3696
* CVE-2021-3697
* CVE-2022-28733
* CVE-2022-28734
* CVE-2022-28735
* CVE-2022-28736
* CVE-2022-28737
*******************************************************************************
We haven't released a shim yet, so possibly this doesn't apply anyway.

The general idea about security updates is: By using the latest sources provided by Debian (see above), we assume we are not affected by any of these issues listed above.

*******************************************************************************
### If these fixes have been applied, have you set the global SBAT generation on your GRUB binary to 3?
*******************************************************************************
Yes

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
*******************************************************************************
1. No
2. Yes

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
*******************************************************************************
We follow the stable Linux kernel series, currently on 6.1.x. These commits are included there.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
The majority of the patches are the result of customer reports about devices not properly working. So it's about enhancing lists of device IDs in various places, device support or quirks list. Occasionally we work around noisy logging or upstream kernel changes that introduced more harm than benefit.

And there are the patches that support lockdown (see below).

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We are not using vendor_db.

*******************************************************************************
### If you are re-using a previously used (CA) certificate, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs to vendor_dbx in shim in order to prevent GRUB2 from being able to chainload those older GRUB2 binaries. If you are changing to a new (CA) certificate, this does not apply.
### Please describe your strategy.
*******************************************************************************
We are not re-using certificates.

*******************************************************************************
### What OS and toolchain must we use to reproduce this build?  Include where to find it, etc.  We're going to try to reproduce your build as closely as possible to verify that it's really a build of the source tree you tell us it is, so these need to be fairly thorough. At the very least include the specific versions of gcc, binutils, and gnu-efi which were used, and where to find those binaries.
### If the shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case and what the differences would be.
*******************************************************************************
The build was done on Ubuntu 20.04 ("focal"), so it's

- gcc: 4:9.3.0-1ubuntu2
- binutils: 2.34-6ubuntu1.3
- gnu-efi as included in the shim 15.7 tar ball

*******************************************************************************
### Which files in this repo are the logs for your build?
This should include logs for creating the buildroots, applying patches, doing the build, creating the archives, etc.
*******************************************************************************
There are two log files:

- build-chroot.log: This contains
  * Using debootstrap to set up a build chroot
  * Creating a "build" user for doing the build later
  * Updating the chroot, and installing the build dependencies
  * A dump of the sources.list file
  * A list of the installed packages with version information (just "dpkg -l")
  * Installing the shim sources
  * The actual build
- build-docker.log: The log of the docker build, using the provided Dockerfile

*******************************************************************************
### What changes were made since your SHIM was last signed?
*******************************************************************************
Not applicable as this is the first shim to be signed.

*******************************************************************************
### What is the SHA256 hash of your final SHIM binary?
*******************************************************************************
4ef1179453b093781de767ea5821da8b1abd58eaf00ef56c0c85e1852b93477d  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your SHIM?
*******************************************************************************
The private key is stored on a HSM (yubikey) to avoid leakage of that sensitive material.

The system to do the signing lives on real hardware, is not connected to a network and access to it is limited.

Each signing creates a report document that includes timestamps, file names, hash sums (sha1 and sha256). This is archived in a local git repository, together with the files themselves, pre and post state.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the SHIM?
*******************************************************************************
No

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( grub2, fwupd, fwupdate, shim + all child shim binaries )?
### Please provide exact SBAT entries for all SBAT binaries you are booting or planning to boot directly through shim.
### Where your code is only slightly modified from an upstream vendor's, please also preserve their SBAT entries to simplify revocation.
*******************************************************************************

shim:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,3,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.elux,1,Unicon,grub2,15.7,mail:product-security@unicon.com

grub2:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,3,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.debian,4,Debian,grub2,2.06-3~deb11u5,https://tracker.debian.org/pkg/grub2
grub.elux,1,Unicon,grub2,grub2,2.06-3~deb11u5unicon1,mail:product-security@unicon.com

fwupd:
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.2,https://github.com/fwupd/fwupd-efi
fwupd-efi.ubuntu,1,Ubuntu,fwupd,1.2-2~20.04.1,https://launchpad.net/ubuntu/+source/fwupd
fwupd-efi.elux,1,Unicon,fwupd,1.2-2~20.04.1unicon1,mail:product-security@unicon.com

*******************************************************************************
### Which modules are built into your signed grub image?
*******************************************************************************
As mentioned earlier, we will follow Debian's policy on building the grub images as closely as possible. Their list (`from debian/build-efi-images`) is:

all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux linuxefi loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks lvm mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search search_fs_file search_fs_uuid search_label sleep squash4 test tpm true video xfs zfs zfscrypt zfsinfo

and will will not remove anything for simplicity. We also include

* net
* tftp


*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB or other)?
*******************************************************************************
The used bootloader is grub2, sources are as provided by Debian 11 ("bullseye"), version 2.06-3~deb11u5.

*******************************************************************************
### If your SHIM launches any other components, please provide further details on what is launched.
*******************************************************************************
We might launch fwupd ("Firmware update daemon"), using the version from Ubuntu focal. Only change is adding our SBAT entry.

*******************************************************************************
### If your GRUB2 launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
*******************************************************************************
No other binaries are launched from grub.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
*******************************************************************************
The kernel enforces signature validation on any loaded module, see description of patches below. Proper functionality is part of the release test procedure.

Neither kexec nor hibernation are enabled in the kernel configuration.

The Sources of all out-of-tree modules are taken from a trusted source (usually Ubuntu) and validated before building and signing.

*******************************************************************************
### Does your SHIM load any loaders that support loading unsigned kernels (e.g. GRUB)?
*******************************************************************************
No

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
We follow the stable Linux kernel series.

Additionally, we picked the patches

    efi-add-an-efi_secure_boot-flag-to-indicate-secure-b.patch
    efi-lock-down-the-kernel-if-booted-in-secure-boot-mo.patch

from the Debian kernel to enforce signature validation of kernel modules if and only if a system was booted in secure boot.

*******************************************************************************
### Add any additional information you think we may need to validate this shim.
*******************************************************************************
Certificate is
42892b947de589fa0fa0717c67ad60826404851d7b46d407be9cfc4270c41c35  uc-sb-signing.crt.pem
