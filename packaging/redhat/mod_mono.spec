%define pkg_version 0.3
%define xsp_version 0.3
%define module_path /usr/lib/httpd/modules

Summary: Mono module for Apache 2
Name: mod_mono
Version: 0.3.6
Release: 1
License: The Apache License
Group: System Environment/Daemons
Source0: http://www.apacheworld.org/modmono/%{name}-%{pkg_version}.tar.gz
Source1: xsp-%{xsp_version}.tar.gz
Source2: mono.conf
BuildRoot: /var/tmp/%{name}-root
BuildRequires: httpd-devel
BuildRequires: mono
BuildRequires: autoconf
Requires: httpd
Requires: httpd-mmn = %(cat %{_includedir}/httpd/.mmn)

%description
This module allows you to run ASP.NET pages on Unix with Apache and Mono.

%prep
%setup -n %{name}-%{pkg_version} -a 1

%build
# Build sample ASP.NET pages from xsp distribution
pushd xsp-%{xsp_version}
make
make install
popd

# Build Apache Module
autoconf
%configure --with-apxs=/usr/sbin/apxs
make

# Build Mono DLL
pushd src
make -f makedll.mak
popd

%install
mkdir -p $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf.d
mkdir -p $RPM_BUILD_ROOT/%{module_path}
mkdir -p $RPM_BUILD_ROOT/var/www/html/mono
mkdir -p $RPM_BUILD_ROOT/var/www/.wapi

cp %{SOURCE2} $RPM_BUILD_ROOT/%{_sysconfdir}/httpd/conf.d
install src/.libs/libmod_mono.so $RPM_BUILD_ROOT/%{module_path}
install src/ModMono.dll $RPM_BUILD_ROOT/%{_libdir}
cp -r xsp-%{xsp_version}/server/test/* $RPM_BUILD_ROOT/var/www/html/mono

%clean
rm -rf ${RPM_BUILD_ROOT}

%files
%defattr(-,root,root)
%doc ChangeLog COPYING INSTALL NEWS README
%{_sysconfdir}/httpd/conf.d/mono.conf
%{_libdir}/ModMono.dll
%{_libdir}/httpd/modules/libmod_mono.so
%defattr(-,apache,apache)
%{_var}/www/html/mono/
%{_var}/www/.wapi/

%changelog
* Mon Feb 03 2003 Daniel Lopez Ridruejo <daniel @ rawbyte.com>
- Use --with-apxs
- License is Apache-style
- Change ownership to apache user
- Create .wapi directory

* Mon Feb 03 2003 David Hollis <dhollis@davehollis.com>
- 0.3.4

* Wed Jan 15 2003 David Hollis <dhollis@davehollis.com>
- Initial spec

