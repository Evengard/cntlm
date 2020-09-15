PLEASE NOTE THAT THIS FORK IS NOT MAINTAINED! For the maintained fork please refer to https://github.com/versat/cntlm

```
Installation using packages
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Most of the popular distros contain cntlm packages.n their repositories.
You can use the procedures described below to prepare a package of current cntlm
version if desired.

NOTE: generating packages traditionally requires root privileges (to be able to set
proper ownership and permissions on package members). You can overcome that using
fakeroot. However, to install your packages you have to be root.

*** SOURCE TARBALL ***

	$ make tgz
	or
	$ make tbz2

*** DEBIAN PACKAGES ***

1) Quick way:

	$ make deb

2) From Debian/Ubuntu repository:

	Get these files (e.g. apt-get source cntlm):

	cntlm_0.XX-X.diff.gz
	cntlm_0.XX-X.dsc
	cntlm_0.XX.orig.tar.gz

	Compile:

	$ dpkg-source -x cntlm_0.XX-Y.dsc
	$ cd cntlm-0.XX/
	$ dpkg-buildpackage -b -rfakeroot

	Upon installation, the package takes care of creating a dedicated user for
	cntlm, init script integration, manages eventual configuration file updates
	with new upstream versions, things like restart of the daemon after future
	updates, etc. You can later revert all these changes with one command, should
	you decide to remove cntlm from your system.


*** RPM FROM SCRATCH ***

1) Quick way:

	$ make rpm			# you'll need root privs. or fakeroot utility

2) Detailed howto (or if make rpm doesn't work for you)

	To build an RPM package from scratch, as root change to
	/usr/src/[redhat|rpm|whatever]/SOURCES

	Copy there all files from cntlm's rpm/ directory plus appropriate version of
	the source tar.bz2 (see SOURCE TARBALL section above) and type:

	$ rpmbuild -ba cntlm.spec

	Shortly after, you'll have source and binary RPMs ready in your ../SRPMS, resp.
	../RPMS directories.

	If your build cannot find the default config file in /etc, you probably have
	broken RPM build environment. You should add this to your ~/.rpmmacros:
	%_sysconfdir	/etc

*** RPM FROM *.src.rpm ***

	If you just want to create a binary package from src.rpm, as root type:

	$ rpmbuild --rebuild pkgname.src.rpm

	Resulting binary RPM will be at /usr/src/..../RPMS

	If your build cannot find the default config file in /etc, you probably have
	broken RPM build environment. You should add this to your ~/.rpmmacros:
	%_sysconfdir	/etc

*** WINDOWS INSTALLER ***

	Install CygWin and include at least the ghostscript, zip and libgcc packages.

	In case you are using a 64-bit version of CygWin: rename cyggcc_s-1.dll to
	cyggcc_s-seh-1.dll in Makefile and win/setup.iss.
	
	Start a CygWin console by using the shortcut on your desktop or startup menu.
	
	From within the CygWin command shell:
	
	$ cd /cygdrive/yourdrive/your_ctnlm_src_location

	$ ./configure
	$ make

	Prepare all binaries, manuals, config templates, Start Menu links and InnoSetup
	project definition file:

	$ make win

	Then run InnoSetup compiler to pack it all into an automatic installer EXE:

	$ /your/path/to/ISCC.exe win/setup.iss
	or
	Open folder "win" in explorer, right click "setup.iss" and select "Compile".

	Both with generate an installer in the "cntlm" folder.

Traditional installation
~~~~~~~~~~~~~~~~~~~~~~~~
First, you have to compile cntlm. Using the Makefile, this should be very easy:

$ ./configure
$ make
$ make install

Cntlm does not require any dynamic libraries and there are no dependencies you
have to satisfy before compilation, except for libpthreads. This library is
required for all threaded applications and is very likely to be part of your
system already, because it comes with libc. Next, install cntlm onto your
system like so:

Default installation directories are /usr/sbin, /usr/share/man and /etc. Should
you want to install cntlm into a different location, change the DESTDIR
installation prefix (from "/") to add a different installation prefix (e.g.
/usr/local).  To change individual directories, use BINDIR, MANDIR and
SYSCONFDIR:

$ make SYSCONFDIR=/etc BINDIR=/usr/bin MANDIR=/usr/share/man
$ make install SYSCONFDIR=/etc BINDIR=/usr/bin MANDIR=/usr/share/man

Cntlm is compiled with system-wide configuration file by default. That means
whenever you run cntlm, it looks into a hardcoded path (SYSCONFDIR) and tries
to load cntml.conf. You cannot make it not to do so, unless you use -c with an
alternative file or /dev/null. This is standard behaviour and probably what you
want. On the other hand, some of you might not want to use cntlm as a daemon
started by init scripts and you would prefer setting up everything on the
command line. This is possible, just comment out SYSCONFDIR variable definition
in the Makefile before you compile cntlm and it will remove this feature.

Installation includes the main binary, the man page (see "man cntlm") and if
the default config feature was not removed, it also installs a configuration
template. Please note that unlike bin and man targets, existing configuration
is never overwritten during installation. In the doc/ directory you can find
among other things a file called "cntlmd". It can be used as an init.d script.


Architectures
~~~~~~~~~~~~~
The build system now has an autodetection of the build arch endianness. Every
common CPU and OS out there is supported, including Windows, MacOS X, Linux,
*BSD, AIX.


Compilers
~~~~~~~~~
Cntlm is tested against GCC and IBM XL C/C++, other C compilers will work
for you too. There are no compiler specific directives and options AFAIK.
compilers might work for you (then again, they might not). Specific
Makefiles for different compilers are supported by the ./configure script
(e.g. Makefile.xlc)


Contact
~~~~~~~
David Kubicek <dave@awk.cz>
