Name:           kindlyguard
Version:        %{version}
Release:        1%{?dist}
Summary:        Security-focused MCP server protecting against unicode attacks

License:        Apache-2.0
URL:            https://github.com/samduchaine/kindly-guard
Source0:        https://github.com/samduchaine/kindly-guard/archive/v%{version}.tar.gz

BuildRequires:  rust >= 1.75
BuildRequires:  cargo
BuildRequires:  gcc
BuildRequires:  make

%description
KindlyGuard is a security-focused Model Context Protocol (MCP) server that
protects against unicode attacks, injection attempts, and other threats.

Features:
- Unicode security threat detection (homographs, bidi, zero-width)
- Injection prevention (SQL, command, LDAP, XSS)
- Real-time threat monitoring dashboard
- MCP protocol integration
- High-performance scanning with SIMD optimization

This package includes both the MCP server and CLI tools.

%prep
%autosetup -n kindly-guard-%{version}

%build
cargo build --release

%install
install -D -m 755 target/release/kindly-guard %{buildroot}%{_bindir}/kindly-guard
install -D -m 755 target/release/kindly-guard-cli %{buildroot}%{_bindir}/kindly-guard-cli
install -D -m 644 LICENSE %{buildroot}%{_datadir}/licenses/%{name}/LICENSE
install -D -m 644 README.md %{buildroot}%{_datadir}/doc/%{name}/README.md

# Install man pages if they exist
if [ -d docs/man ]; then
    install -D -m 644 docs/man/kindly-guard.1 %{buildroot}%{_mandir}/man1/kindly-guard.1
    install -D -m 644 docs/man/kindly-guard-cli.1 %{buildroot}%{_mandir}/man1/kindly-guard-cli.1
fi

# Install systemd service file
install -D -m 644 systemd/kindlyguard.service %{buildroot}%{_unitdir}/kindlyguard.service

%files
%license LICENSE
%doc README.md SECURITY.md
%{_bindir}/kindly-guard
%{_bindir}/kindly-guard-cli
%{_mandir}/man1/kindly-guard.1*
%{_mandir}/man1/kindly-guard-cli.1*
%{_unitdir}/kindlyguard.service

%post
%systemd_post kindlyguard.service

%preun
%systemd_preun kindlyguard.service

%postun
%systemd_postun_with_restart kindlyguard.service

%changelog
* Thu Jan 20 2025 KindlyGuard Team <support@kindlyguard.dev> - %{version}-1
- Initial RPM release