This repo is for review of requests for signing shim. To create a request for review:

- clone this repo (preferably fork it)
- edit the template below
- add the shim.efi to be signed
- add build logs
- add any additional binaries/certificates/SHA256 hashes that may be needed
- commit all of that
- tag it with a tag of the form "myorg-shim-arch-YYYYMMDD"
- push it to GitHub
- file an issue at https://github.com/rhboot/shim-review/issues with a link to your tag
- approval is ready when the "accepted" label is added to your issue

Note that we really only have experience with using GRUB2 or systemd-boot on Linux, so
asking us to endorse anything else for signing is going to require some convincing on
your part.

Hint: check the [docs](./docs/) directory in this repo for guidance on submission and getting your shim signed.

Here's the template:

*******************************************************************************
### What organization or people are asking to have this signed?
*******************************************************************************
Organization name and website:
Unicon GmbH
Ludwig-Erhard-Allee 26
76131 Karlsruhe
Tel.: +49 (721) 96451-0

*******************************************************************************
### What's the legal data that proves the organization's genuineness?
The reviewers should be able to easily verify, that your organization is a legal entity, to prevent abuse.
Provide the information, which can prove the genuineness with certainty.
*******************************************************************************
Company/tax register entries or equivalent:
(a link to the organization entry in your jurisdiction's register will do)

[your text here]

The public details of both your organization and the issuer in the EV certificate used for signing .cab files at Microsoft Hardware Dev Center File Signing Services.
(**not** the CA certificate embedded in your shim binary)

Example:

```
Issuer: O=MyIssuer, Ltd., CN=MyIssuer EV Code Signing CA
Subject: C=XX, O=MyCompany, Inc., CN=MyCompany, Inc.
```

[your text here]

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
### Were these binaries created from the 16.0 shim release tar?
Please create your shim binaries starting with the 16.0 shim release tar file: https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2

This matches https://github.com/rhboot/shim/releases/tag/16.0 and contains the appropriate gnu-efi source.

Make sure the tarball is correct by verifying your download's checksum with the following ones:

```
7b518edd63eb840081912f095ed1487a  shim-16.0.tar.bz2
c2453b9b3c02bc01eea248e9cf634a179ff8828c  shim-16.0.tar.bz2
d503f778dc75895d3130da07e2ff23d2393862f95b6cd3d24b10cbd4af847217  shim-16.0.tar.bz2
b4367f3b1e0716d093f4230902e392d3228bd346e2e07a9377c498d8b3b08a5c0ad25c31aa03af66f54648618074a29b55a3e51925e5cfe5c7ac97257bd25880  shim-16.0.tar.bz2
```

Make sure that you've verified that your build process uses that file
as a source of truth (excluding external patches) and its checksum
matches. You can also further validate the release by checking the PGP
signature: there's [a detached
signature](https://github.com/rhboot/shim/releases/download/16.0/shim-16.0.tar.bz2.asc)

The release is signed by the maintainer Peter Jones - his master key
has the fingerprint `B00B48BC731AA8840FED9FB0EED266B70F4FEF10` and the
signing sub-key in the signature here has the fingerprint
`02093E0D19DDE0F7DFFBB53C1FD3F540256A1372`. A copy of his public key
is included here for reference:
[pjones.asc](https://github.com/rhboot/shim-review/pjones.asc)

Once you're sure that the tarball you are using is correct and
authentic, please confirm this here with a simple *yes*.

A short guide on verifying public keys and signatures should be available in the [docs](./docs/) directory.
*******************************************************************************
The build is based on the https://github.com/rhboot/ git repository, tag 15.8

*******************************************************************************
### URL for a repo that contains the exact code which was built to result in your binary:
Hint: If you attach all the patches and modifications that are being used to your application, you can point to the URL of your application here (*`https://github.com/YOUR_ORGANIZATION/shim-review`*).

You can also point to your custom git servers, where the code is hosted.
*******************************************************************************
https://github.com/UniconSoftware/shim

*******************************************************************************
### What patches are being applied and why:
Mention all the external patches and build process modifications, which are used during your building process, that make your shim binary be the exact one that you posted as part of this application.
*******************************************************************************
None

*******************************************************************************
### Do you have the NX bit set in your shim? If so, is your entire boot stack NX-compatible and what testing have you done to ensure such compatibility?

See https://techcommunity.microsoft.com/t5/hardware-dev-center/nx-exception-for-shim-community/ba-p/3976522 for more details on the signing of shim without NX bit.
*******************************************************************************
That bit is currently not set in shim and grub2, but in the kernel. We do not the respective build systems and just wait them to enable it once they consider it wise to do so.

*******************************************************************************
### What exact implementation of Secure Boot in GRUB2 do you have? (Either Upstream GRUB2 shim_lock verifier or Downstream RHEL/Fedora/Debian/Canonical-like implementation)
Skip this, if you're not using GRUB2.
*******************************************************************************
Some extra complexity here since we've switched the grub sources between the current, stable release and the future new release.

For "future" releases, we use the sources as provided by Ubuntu 22.04 ("jammy"), currently 2.06-2ubuntu14.4.

For "current" releases, we use the sources as provided by Debian 11 ("bullseye"), currently 2.06-3~deb11u6.

For both, we use the result of dpkg-buildpackage. And we track the respective repositories to learn about any important updates. 

There are local modifications that do not touch the code. They change the embedded configuration, add an additional line to the SBAT record, and handle some gotchas in the test suite.

*******************************************************************************
### Do you have fixes for all the following GRUB2 CVEs applied?
**Skip this, if you're not using GRUB2, otherwise make sure these are present and confirm with _yes_.**

* 2020 July - BootHole
  * Details: https://lists.gnu.org/archive/html/grub-devel/2020-07/msg00034.html
  * CVE-2020-10713
  * CVE-2020-14308
  * CVE-2020-14309
  * CVE-2020-14310
  * CVE-2020-14311
  * CVE-2020-15705
  * CVE-2020-15706
  * CVE-2020-15707
* March 2021
  * Details: https://lists.gnu.org/archive/html/grub-devel/2021-03/msg00007.html
  * CVE-2020-14372
  * CVE-2020-25632
  * CVE-2020-25647
  * CVE-2020-27749
  * CVE-2020-27779
  * CVE-2021-3418 (if you are shipping the shim_lock module)
  * CVE-2021-20225
  * CVE-2021-20233
* June 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-06/msg00035.html, SBAT increase to 2
  * CVE-2021-3695
  * CVE-2021-3696
  * CVE-2021-3697
  * CVE-2022-28733
  * CVE-2022-28734
  * CVE-2022-28735
  * CVE-2022-28736
  * CVE-2022-28737
* November 2022
  * Details: https://lists.gnu.org/archive/html/grub-devel/2022-11/msg00059.html, SBAT increase to 3
  * CVE-2022-2601
  * CVE-2022-3775
* October 2023 - NTFS vulnerabilities
  * Details: https://lists.gnu.org/archive/html/grub-devel/2023-10/msg00028.html, SBAT increase to 4
  * CVE-2023-4693
  * CVE-2023-4692
*******************************************************************************
We haven't released a shim yet, so possibly this doesn't apply anyway.

The general idea about security updates is: By using the latest sources provided by Ubuntu/Debian (see above), we assume we are not affected by any of these issues listed above.

*******************************************************************************
### If shim is loading GRUB2 bootloader, and if these fixes have been applied, is the upstream global SBAT generation in your GRUB2 binary set to 4?
Skip this, if you're not using GRUB2, otherwise do you have an entry in your GRUB2 binary similar to:
`grub,4,Free Software Foundation,grub,GRUB_UPSTREAM_VERSION,https://www.gnu.org/software/grub/`?
*******************************************************************************
Yes

*******************************************************************************
### Were old shims hashes provided to Microsoft for verification and to be added to future DBX updates?
### Does your new chain of trust disallow booting old GRUB2 builds affected by the CVEs?
If you had no previous signed shim, say so here. Otherwise a simple _yes_ will do.
*******************************************************************************
1. No
2. Yes

*******************************************************************************
### If your boot chain of trust includes a Linux kernel:
### Is upstream commit [1957a85b0032a81e6482ca4aab883643b8dae06e "efi: Restrict efivar_ssdt_load when the kernel is locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=1957a85b0032a81e6482ca4aab883643b8dae06e) applied?
### Is upstream commit [75b0cea7bf307f362057cc778efe89af4c615354 "ACPI: configfs: Disallow loading ACPI tables when locked down"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=75b0cea7bf307f362057cc778efe89af4c615354) applied?
### Is upstream commit [eadb2f47a3ced5c64b23b90fd2a3463f63726066 "lockdown: also lock down previous kgdb use"](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eadb2f47a3ced5c64b23b90fd2a3463f63726066) applied?
Hint: upstream kernels should have all these applied, but if you ship your own heavily-modified older kernel version, that is being maintained separately from upstream, this may not be the case.
If you are shipping an older kernel, double-check your sources; maybe you do not have all the patches, but ship a configuration, that does not expose the issue(s).
*******************************************************************************
[your text here]

*******************************************************************************
### How does your signed kernel enforce lockdown when your system runs
### with Secure Boot enabled?
Hint: If it does not, we are not likely to sign your shim.
*******************************************************************************
We follow the stable Linux kernel series, currently on 6.1.y and 6.6.y. These commits are included there.

*******************************************************************************
### Do you build your signed kernel with additional local patches? What do they do?
*******************************************************************************
The majority of the patches are the result of customer reports about devices not properly working. So it's about enhancing lists of device IDs in various places, device support or quirks list. Occasionally we work around noisy logging or upstream kernel changes that introduced more harm than benefit.

And there are the patches that support lockdown (see below).

*******************************************************************************
### Do you use an ephemeral key for signing kernel modules?
### If not, please describe how you ensure that one kernel build does not load modules built for another kernel.
*******************************************************************************
We are indeed using an ephemeral key for that purpose. Extra care is taken to make sure this key cannot leak, for example by invalidating it as soon as it is no longer needed.

*******************************************************************************
### If you use vendor_db functionality of providing multiple certificates and/or hashes please briefly describe your certificate setup.
### If there are allow-listed hashes please provide exact binaries for which hashes are created via file sharing service, available in public with anonymous access for verification.
*******************************************************************************
We are not using vendor_db.

*******************************************************************************
### If you are re-using the CA certificate from your last shim binary, you will need to add the hashes of the previous GRUB2 binaries exposed to the CVEs mentioned earlier to vendor_dbx in shim. Please describe your strategy.
This ensures that your new shim+GRUB2 can no longer chainload those older GRUB2 binaries with issues.

If this is your first application or you're using a new CA certificate, please say so here.
*******************************************************************************
We are not re-using certificates.

*******************************************************************************
### Is the Dockerfile in your repository the recipe for reproducing the building of your shim binary?
A reviewer should always be able to run `docker build .` to get the exact binary you attached in your application.

Hint: Prefer using *frozen* packages for your toolchain, since an update to GCC, binutils, gnu-efi may result in building a shim binary with a different checksum.

If your shim binaries can't be reproduced using the provided Dockerfile, please explain why that's the case, what the differences would be and what build environment (OS and toolchain) is being used to reproduce this build? In this case please write a detailed guide, how to setup this build environment from scratch.
*******************************************************************************
The build was done on Ubuntu 22.04 ("jammy"), so it's

- gcc: 4:11.2.0-1ubuntu1
- binutils: 2.38-3ubuntu1
- gnu-efi Subproject commit 328951d3dcb5ff97f5a7c7a362b006626fada000

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
### What changes were made in the distro's secure boot chain since your SHIM was last signed?
For example, signing new kernel's variants, UKI, systemd-boot, new certs, new CA, etc..

Skip this, if this is your first application for having shim signed.
*******************************************************************************
Not applicable as this is the first shim to be signed.

*******************************************************************************
### What is the SHA256 hash of your final shim binary?
*******************************************************************************
78a979f518efdcc0c43f7cc8b49c369bf601182dd37f9d3ade9f139befe3b1ef  shimx64.efi

*******************************************************************************
### How do you manage and protect the keys used in your shim?
Describe the security strategy that is used for key protection. This can range from using hardware tokens like HSMs or Smartcards, air-gapped vaults, physical safes to other good practices.
*******************************************************************************
The private key is stored on a HSM (yubikey) to avoid leakage of that sensitive material.

The system to do the signing lives on real hardware, is not connected to a network and access to it is limited.

Each signing creates a report document that includes timestamps, file names, hash sums (sha1 and sha256). This is archived in a local git repository, together with the files themselves, pre and post state.

*******************************************************************************
### Do you use EV certificates as embedded certificates in the shim?
A _yes_ or _no_ will do. There's no penalty for the latter.
*******************************************************************************
[your text here]

*******************************************************************************
### Are you embedding a CA certificate in your shim?
A _yes_ or _no_ will do. There's no penalty for the latter. However,
if _yes_: does that certificate include the X509v3 Basic Constraints
to say that it is a CA? See the [docs](./docs/) for more guidance
about this.
*******************************************************************************
No

*******************************************************************************
### Do you add a vendor-specific SBAT entry to the SBAT section in each binary that supports SBAT metadata ( GRUB2, fwupd, fwupdate, systemd-boot, systemd-stub, shim + all child shim binaries )?
### Please provide the exact SBAT entries for all binaries you are booting directly through shim.
Hint: The history of SBAT and more information on how it works can be found [here](https://github.com/rhboot/shim/blob/main/SBAT.md). That document is large, so for just some examples check out [SBAT.example.md](https://github.com/rhboot/shim/blob/main/SBAT.example.md)

If you are using a downstream implementation of GRUB2 (e.g. from Fedora or Debian), make sure you have their SBAT entries preserved and that you **append** your own (don't replace theirs) to simplify revocation.

**Remember to post the entries of all the binaries. Apart from your bootloader, you may also be shipping e.g. a firmware updater, which will also have these.**

Hint: run `objcopy --only-section .sbat -O binary YOUR_EFI_BINARY /dev/stdout` to get these entries. Paste them here. Preferably surround each listing with three backticks (\`\`\`), so they render well.
*******************************************************************************

shim:
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
shim,4,UEFI shim,shim,1,https://github.com/rhboot/shim
shim.elux,1,Unicon,shim,15.8,mail:product-security@unicon.com

grub2 ("future"):
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.ubuntu,1,Ubuntu,grub2,2.06-2ubuntu14.4,https://www.ubuntu.com/
grub.elux,1,Unicon,grub2,2.06-2ubuntu14.4elux7,mail:product-security@unicon.com

grub2 ("current"):
sbat,1,SBAT Version,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
grub,4,Free Software Foundation,grub,2.06,https://www.gnu.org/software/grub/
grub.debian,4,Debian,grub2,2.06-3~deb11u6,https://tracker.debian.org/pkg/grub2
grub.elux,1,Unicon,grub2,2.06-3~deb11u6unicon1,mail:product-security@unicon.com

fwupd:
sbat,1,UEFI shim,sbat,1,https://github.com/rhboot/shim/blob/main/SBAT.md
fwupd-efi,1,Firmware update daemon,fwupd-efi,1.2,https://github.com/fwupd/fwupd-efi
fwupd-efi.ubuntu,1,Ubuntu,fwupd,1.2-2~20.04.1,https://launchpad.net/ubuntu/+source/fwupd
fwupd-efi.elux,1,Unicon,fwupd,1.2-2~20.04.1unicon1,mail:product-security@unicon.com

*******************************************************************************
### If shim is loading GRUB2 bootloader, which modules are built into your signed GRUB2 image?
Skip this, if you're not using GRUB2.

Hint: this is about those modules that are in the binary itself, not the `.mod` files in your filesystem.
*******************************************************************************
As mentioned earlier, we will follow Ubuntu's/Debian's policy on building the grub images as closely as possible. Their list (from `debian/build-efi-images`) is for "current":

all_video boot btrfs cat chain configfile cpuid cryptodisk echo efifwsetup efinet ext2 f2fs fat font gcry_arcfour gcry_blowfish gcry_camellia gcry_cast5 gcry_crc gcry_des gcry_dsa gcry_idea gcry_md4 gcry_md5 gcry_rfc2268 gcry_rijndael gcry_rmd160 gcry_rsa gcry_seed gcry_serpent gcry_sha1 gcry_sha256 gcry_sha512 gcry_tiger gcry_twofish gcry_whirlpool gettext gfxmenu gfxterm gfxterm_background gzio halt help hfsplus iso9660 jfs jpeg keystatus linux linuxefi loadenv loopback ls lsefi lsefimmap lsefisystab lssal luks lvm mdraid09 mdraid1x memdisk minicmd normal ntfs part_apple part_gpt part_msdos password_pbkdf2 play png probe raid5rec raid6rec reboot regexp search search_fs_file search_fs_uuid search_label sleep squash4 test tpm true video xfs zfs zfscrypt zfsinfo

where "future", in accordance with Ubuntu, lacks f2fs and jfs, but adds smbios, and we do not remove anything for simplicity.

We however include

* net
* tftp

*******************************************************************************
### If you are using systemd-boot on arm64 or riscv, is the fix for [unverified Devicetree Blob loading](https://github.com/systemd/systemd/security/advisories/GHSA-6m6p-rjcq-334c) included?
*******************************************************************************
Not applicable

*******************************************************************************
### What is the origin and full version number of your bootloader (GRUB2 or systemd-boot or other)?
*******************************************************************************
The used bootloader is grub2, sources are taken from, as mentioned above:

* "current" Debian 11 ("bullseye"), version 2.06-3~deb11u6
* "future" Ubuntu 22.04 ("jammy"), version 2.06-2ubuntu14.4

*******************************************************************************
### If your shim launches any other components apart from your bootloader, please provide further details on what is launched.
Hint: The most common case here will be a firmware updater like fwupd.
*******************************************************************************
We might launch fwupd ("Firmware update daemon"), using the version from Ubuntu focal. Only change is adding our SBAT entry.

*******************************************************************************
### If your GRUB2 or systemd-boot launches any other binaries that are not the Linux kernel in SecureBoot mode, please provide further details on what is launched and how it enforces Secureboot lockdown.
Skip this, if you're not using GRUB2 or systemd-boot.
*******************************************************************************
No other binaries are launched from grub.

*******************************************************************************
### How do the launched components prevent execution of unauthenticated code?
Summarize in one or two sentences, how your secure bootchain works on higher level.
*******************************************************************************
The kernel enforces signature validation on any loaded module, see description of patches below. Proper functionality is part of the release test procedure.

Neither kexec nor hibernation are enabled in the kernel configuration.

The Sources of all out-of-tree modules are taken from a trusted source (usually Ubuntu) and validated before building and signing.

*******************************************************************************
### What kernel are you using? Which patches does it includes to enforce Secure Boot?
*******************************************************************************
We follow the stable Linux kernel series.

Additionally, we picked the patches

    efi-add-an-efi_secure_boot-flag-to-indicate-secure-b.patch
    efi-lock-down-the-kernel-if-booted-in-secure-boot-mo.patch

from the Debian kernel to enforce signature validation of kernel modules if and only if a system was booted in secure boot.


### Does your shim load any loaders that support loading unsigned kernels (e.g. certain GRUB2 configurations)?
*******************************************************************************
Short answer: No.

Technically yes as we use grub2, but grub2 itself will refuse to load unsigned kernels if bootet in secure boot mode. And we certainly do not alter that behaviour.

*******************************************************************************
### What kernel are you using? Which patches and configuration does it include to enforce Secure Boot?
*******************************************************************************
[your text here]

*******************************************************************************
### What contributions have you made to help us review the applications of other applicants?
The reviewing process is meant to be a peer-review effort and the best way to have your application reviewed faster is to help with reviewing others. We are in most cases volunteers working on this venue in our free time, rather than being employed and paid to review the applications during our business hours.

A reasonable timeframe of waiting for a review can reach 2-3 months. Helping us is the best way to shorten this period. The more help we get, the faster and the smoother things will go.

For newcomers, the applications labeled as [*easy to review*](https://github.com/rhboot/shim-review/issues?q=is%3Aopen+is%3Aissue+label%3A%22easy+to+review%22) are recommended to start the contribution process.
*******************************************************************************
[your text here]

*******************************************************************************
### Add any additional information you think we may need to validate this shim signing application.
*******************************************************************************
Certificate is
6b0977b60f9691a0e7e78c4f13e962a93ac595759fb264c69f5ead07cab68b58  uc-sb-signing.crt.der
