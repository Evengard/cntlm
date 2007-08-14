Summary:        Fast NTLM authentication proxy with tunneling
Name:           cntlm
Version:        0.33
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
if [ "$1" -eq 1 ]; then
    /usr/sbin/useradd -s /sbin/nologin -m -r -d /var/run/cntlm cntlm 2>/dev/null
fi    
:

%post
if [ "$1" -eq 1 ]; then
    /sbin/chkconfig --add cntlmd
fi
:

%preun
if [ "$1" -eq 0 ]; then
        /sbin/service cntlmd stop &> /dev/null
        /sbin/chkconfig --del cntlmd
fi
:

%postun
if [ "$1" -eq 0 ]; then
    /usr/sbin/userdel -r cntlm 2>/dev/null
fi    
:

%changelog
* Wed Jul 26 2007 Radislav Vrnata <vrnata at gedas.cz>
- Version 0.33-1
- fixed %pre, %post, %preun, %postun macros bugs affecting upgrade process

* Mon May 30 2007 Since 0.28 maintained by <dave@awk.cz>

* Mon May 28 2007 Radislav Vrnata <vrnata at gedas.cz>
- Version 0.27
- First release
