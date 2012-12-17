Summary: Apache Module mod_dims
Name: mod_dims
Version: 3.1.0
Release: 4.is24
License: APL
Vendor: BeetleBugOrg at GitHub
Packager: $Id:$
Group: System Environment/Daemons
Source0: autorun.sh

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


%build
/bin/sh ./%{buildroot}/autorun.sh || die "Could not prepare autoconf environment"

export LDFLAGS="$LDFLAGS -L/usr/lib64/httpd"
export CFLAGS="$CFLAGS -I/usr/include/httpd -I/usr/include/ImageMagick"

%configure
make %{?_smp_mflags}

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc

%changelog

