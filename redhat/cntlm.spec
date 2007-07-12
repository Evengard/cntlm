Summary:        Fast NTLM authentication proxy with tunneling
Name:           cntlm
Version:        0.32
Release:        1%{?dist}
License:        GNU GPL V2
Group:          System Environment/Daemons
URL:            http://cntlm.sourceforge.net/
Source0:        %{name}-%{version}.tar.gz
Source1:        cntlm.init
Source2:        cntlm.sysconfig
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Requires(pre): shadow-utils
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig /sbin/service

%description
Cntlm is a fast and efficient NTLM proxy, with support for TCP/IP tunneling,
authenticated connection caching, ACLs, proper daemon logging and behaviour
and much more. It has up to ten times faster responses than similar NTLM
proxies, while using by orders or magnitude less RAM and CPU. Manual page 
contains detailed information.

%prep
%setup -q -n %{name}-%{version}

%build			
make SYSCONFDIR=%{_sysconfdir} \
             BINDIR=%{_sbindir} \
             MANDIR=%{_mandir}

%install
rm -rf $RPM_BUILD_ROOT

%makeinstall SYSCONFDIR=$RPM_BUILD_ROOT/%{_sysconfdir} \
             BINDIR=$RPM_BUILD_ROOT/%{_sbindir} \
             MANDIR=$RPM_BUILD_ROOT/%{_mandir}

install -D -m 755 %{SOURCE1} $RPM_BUILD_ROOT/%{_initrddir}/cntlmd
install -D -m 644 %{SOURCE2} $RPM_BUILD_ROOT/%{_sysconfdir}/sysconfig/cntlmd

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root,-)
%doc LICENSE README COPYRIGHT
%{_sbindir}/cntlm
%{_mandir}/man1/cntlm.1*
%config(noreplace) %{_sysconfdir}/cntlm.conf
%config(noreplace) %{_sysconfdir}/sysconfig/cntlmd
%config(noreplace) %{_initrddir}/cntlmd

%pre
/usr/sbin/useradd -s /sbin/nologin -m -r -d /var/run/cntlm cntlm 2>/dev/null || :

%post
/sbin/chkconfig --add cntlmd
:

%preun
if [ "$1" -eq 0 ]; then
        /sbin/service cntlmd stop &> /dev/null
        /sbin/chkconfig --del cntlmd
fi
:

%postun
rm -rf %{_sysconfdir}/cntlm.conf
/usr/sbin/userdel -r cntlm 2>/dev/null || :

%changelog
* Mon May 30 2007 Since 0.28 maintained by <dave@awk.cz>

* Mon May 28 2007 Radislav Vrnata <vrnata at gedas.cz>
- Version 0.27
- First release
