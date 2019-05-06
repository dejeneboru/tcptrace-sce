Summary: Performs analysis of tcp flows from packet dumps
Name: tcptrace
Version: 6.6.7
Release: jgh_1%{dist}

# [jgh} I've seen no proof of the license beyond DAG using "GPL" in
# his .spec file
License: GPL
Group: Applications/Internet
URL: git@gitlab.quatermass.co.uk:jgh/tcptrace.git

Packager: Jeremy Harris <jgh@redhat.com>
#Vendor:

Source0: tcptrace.%{version}.tgz

BuildRequires: autoconf gcc libpcap-devel
Requires: libpcap

%description
tcptrace is a tool for performing analysis on network packet dumps and
extracting various statistics on the captured traffic as well as generating
several types of graphs.

%prep
%autosetup

%build
autoconf
%configure
%{__make} %{?_smp_mflags}

%install
#makeinstall
%{__install} -D -m0755 tcptrace %{buildroot}%{_bindir}/tcptrace
%{__install} -D -m0755 xpl2gpl %{buildroot}%{_bindir}/xpl2gpl
%{__install} -D -m0644 tcptrace.man %{buildroot}%{_mandir}/man1/tcptrace.1

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%doc ARGS CHANGES COPYING COPYRIGHT FAQ README* THANKS WWW input/
%doc %{_mandir}/man1/tcptrace.1*
%{_bindir}/tcptrace
%{_bindir}/xpl2gpl

%changelog
* Thu Mar 24 2016 Jeremy Harris <jgh@redhat.com> - 6.6.7-jgh_1
- Initial package
