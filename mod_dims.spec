%global _enable_debug_package 0
%global debug_package %{nil}
%global __os_install_post /usr/lib/rpm/brp-compress %{nil}
Summary: Apache Module mod_dims
Name: mod_dims
Version: 3.3.0
Release: 4.is24
License: APL
Vendor: BeetleBugOrg at GitHub
Packager: $Id:$
Group: System Environment/Daemons
Source0: %{name}-%{version}.tar.gz

BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root
BuildArch: x86_64
BuildRequires: ImageMagick-devel
BuildRequires: curl-devel
BuildRequires: httpd-devel


Requires: curl, httpd, ImageMagick

%description
DIMS is a webservice that allows for dynamic image manipulation. It allows for easy image resizing and thumbnail generation directly in HTML pages, eliminating the need to pre-compute different image sizes and store their locations for use on a page.

The source can be found on our github account: https://github.com/Scout24-CoC-MPS/mod_dims.git
which is a fork of https://github.com/beetlebugorg/mod_dims.git

To checkout the source, do: git clone https://github.com/Scout24-CoC-MPS/mod_dims.git

%prep

%setup

%build
./autorun.sh
export LDFLAGS="$LDFLAGS -L/usr/lib64/httpd"
export CFLAGS="$CFLAGS -I/usr/include/httpd -I/usr/include/ImageMagick"

%configure 
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}

install -m 0644 src/.libs/libmod_dims.so -D %{buildroot}%{_libdir}/httpd/modules/mod_dims.so



%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc COPYING README.markdown
%{_libdir}/httpd/modules/mod_dims.so

%changelog
