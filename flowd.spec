%define ver 0.9.1
%define rel 1

# Python < 2.3 (e.g. Redhat 9) doesn't have everything we need, so it may be
# necessary to turn off the python package on older systems
%define python_pkg 1

Summary: The flowd NetFlow collector daemon
Name: flowd
Version: %{ver}
Release: %{rel}
URL: http://www.mindrot.org/flowd.html
Source0: http://www.mindrot.org/files/flowd/flowd-%{ver}.tar.gz
License: BSD
Group: Applications/Internet
BuildRoot: %{_tmppath}/%{name}-%{version}-buildroot
PreReq: initscripts
BuildPreReq: byacc
BuildPreReq: glibc-devel
BuildRequires: %{__python}

%package perl
Summary: Perl API to access flowd logfiles
Group: Applications/Internet
Requires: perl

%if %{python_pkg}
%package python
Summary: Python API to access flowd logfiles
Group: Applications/Internet
Requires: python
%endif

%package tools
Summary: Collection of example flowd tools
Group: Applications/Internet

%package devel
Summary: C API to access flowd logfiles
Group: Applications/Internet

%description
This is flowd, a NetFlow collector daemon intended to be small, fast and secure.

It features some basic filtering to limit or tag the flows that are recorded
and is privilege separated, to limit security exposure from bugs in flowd 
itself.

%description perl
This is a Perl API to the binary flowd network flow log format and an example
reader application

%if %{python_pkg}
%description python
This is a Python API to the binary flowd network flow log format and an 
example reader application
%endif

%description tools
A collection of tools for use with flowd

%description devel
This is a C API to the binary flowd network flow log format.

%prep

%setup

%build
[ -f configure -a -f flowd-config.h.in ] || autoreconf
%configure --enable-gcc-warnings

make

%if %{python_pkg}
./setup.py build
%endif

(cd Flowd-perl ; CFLAGS="$RPM_OPT_FLAGS" perl Makefile.PL \
	PREFIX=$RPM_BUILD_ROOT/usr INSTALLDIRS=vendor; make )

%install
rm -rf $RPM_BUILD_ROOT

%makeinstall

# Misc stuff
install -d $RPM_BUILD_ROOT/var/empty
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
install -m755 flowd.init $RPM_BUILD_ROOT/etc/rc.d/init.d/flowd

# Perl module
(cd Flowd-perl; make install)
find ${RPM_BUILD_ROOT}/usr/lib*/perl5 \
	\( -name perllocal.pod -o -name .packlist \) -exec rm -v {} \;
find ${RPM_BUILD_ROOT}/usr/lib*/perl5 \
	-type f -print | sed "s@^$RPM_BUILD_ROOT@@g" > flowd-perl-filelist
find ${RPM_BUILD_ROOT}%{_mandir} \
	-type f | grep -E '[0-9]pm(.gz)?$' | \
	sed "s@^$RPM_BUILD_ROOT@@g;s@\$@*@" >> \
	flowd-perl-filelist

if [ "$(cat flowd-perl-filelist)X" = "X" ] ; then
    echo "ERROR: EMPTY FILE LIST"
    exit -1
fi

# Python module
%if %{python_pkg}
./setup.py install --optimize 1 --root=$RPM_BUILD_ROOT --record=INSTALLED_FILES
sed -e 's|/[^/]*$||' INSTALLED_FILES | grep "site-packages/" | \
    sort -u | awk '{ print "%attr(755,root,root) %dir " $1}' > INSTALLED_DIRS
cat INSTALLED_FILES INSTALLED_DIRS > INSTALLED_OBJECTS
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%pre
%{_sbindir}/groupadd -r _flowd 2>/dev/null || :
%{_sbindir}/useradd -d /var/empty -s /bin/false -g _flowd -M -r _flowd \
	2>/dev/null || :

%post
/sbin/chkconfig --add flowd

%postun
/sbin/service flowd condrestart > /dev/null 2>&1 || :

%preun
if [ "$1" = 0 ]
then
	/sbin/service flowd stop > /dev/null 2>&1 || :
	/sbin/chkconfig --del flowd
fi

%files
%defattr(-,root,root)
%doc ChangeLog LICENSE README TODO
%dir %attr(0111,root,root) %{_var}/empty
%attr(0600,root,root) %config(noreplace) %{_sysconfdir}/flowd.conf
%attr(0644,root,root) %{_mandir}/man5/flowd.conf.5*
%attr(0644,root,root) %{_mandir}/man8/flowd.8*
%attr(0644,root,root) %{_mandir}/man8/flowd-reader.8*
%attr(0755,root,root) %{_bindir}/flowd-reader
%attr(0755,root,root) %config /etc/rc.d/init.d/flowd
%attr(0755,root,root) %{_sbindir}/flowd

%files perl -f flowd-perl-filelist
%defattr(-,root,root)
%doc reader.pl

%if %{python_pkg}
%files python -f INSTALLED_OBJECTS
%defattr(-,root,root)
%doc reader.py
%endif

%files tools
%defattr(-,root,root)
%doc tools/*

%files devel
%defattr(-,root,root)
%dir %attr(0755,root,root) %{_includedir}/flowd
%attr(0644,root,root) %{_includedir}/flowd/*
%attr(0644,root,root) %{_libdir}/libflowd.a

%changelog
* Wed Nov 03 2004 Damien Miller <djm@mindrot.org>
- Add devel subpackage

* Fri Sep 24 2004 Damien Miller <djm@mindrot.org>
- Add tools subpackage

* Tue Aug 17 2004 Damien Miller <djm@mindrot.org>
- Unbreak for Redhat 9

* Mon Aug 16 2004 Damien Miller <djm@mindrot.org>
- Make Python package optional, Redhat 9 doesn't have support for
  socket.inet_ntop, which flowd.py needs

* Fri Aug 13 2004 Damien Miller <djm@mindrot.org>
- Subpackages for perl and python modules

* Tue Aug 03 2004 Damien Miller <djm@mindrot.org>
- Initial RPM spec

