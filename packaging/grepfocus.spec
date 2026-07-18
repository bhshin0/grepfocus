# GrepFocus RPM spec.
#
# Build locally with packaging/build-rpm.sh; the toolchain comes from the
# invoking user. rust/cargo (rustup) and nodejs/pnpm are deliberately NOT
# declared as BuildRequires: on this host they are user-managed (rustup,
# standalone pnpm), not rpm-managed, so declaring them would only make the
# build fail dependency resolution. This spec targets local rpmbuild, not a
# mock/koji chroot.

# The release profile strips debug symbols (strip = true in Cargo.toml), so
# an automatic debuginfo subpackage would come up empty and fail the build.
%global debug_package %{nil}

Name:           grepfocus
Version:        0.2.0
Release:        1%{?dist}
Summary:        Website and app blocker for Linux

License:        LicenseRef-PolyForm-Shield-1.0.0
URL:            https://github.com/bhshin0/grepfocus
Source0:        grepfocus-%{version}.tar.gz

BuildRequires:  systemd-rpm-macros
BuildRequires:  gcc
BuildRequires:  webkit2gtk4.1-devel
BuildRequires:  gtk3-devel
BuildRequires:  libsoup3-devel
BuildRequires:  javascriptcoregtk4.1-devel

Requires:       nftables
# dlopened by the tray at runtime, invisible to the ELF dependency
# generator — the tray silently fails without it.
Requires:       libayatana-appindicator-gtk3
%{?systemd_requires}

%description
GrepFocus is a website and application blocker for Linux. A root daemon
(grepfocusd) enforces blocks via /etc/hosts and nftables and keeps them in
place until they expire; a desktop GUI with a tray icon (grepfocus-gui)
manages blocks over a local socket.

%prep
%autosetup

%build
# The UI must be built BEFORE cargo: the Tauri build embeds ui/dist at
# compile time, and a plain `cargo build` does not run tauri.conf.json's
# beforeBuildCommand.
pnpm --dir crates/gui/ui install --frozen-lockfile
pnpm --dir crates/gui/ui build
cargo build --release --locked

%install
install -D -m 0755 target/release/grepfocusd %{buildroot}%{_bindir}/grepfocusd
install -D -m 0755 target/release/grepfocus-gui %{buildroot}%{_bindir}/grepfocus-gui

install -D -m 0644 packaging/systemd/grepfocusd.service %{buildroot}%{_unitdir}/grepfocusd.service
install -D -m 0644 packaging/grepfocus.desktop %{buildroot}%{_datadir}/applications/grepfocus.desktop
install -D -m 0644 packaging/grepfocus.desktop %{buildroot}%{_sysconfdir}/xdg/autostart/grepfocus.desktop
# One source of truth: the sources keep /usr/local/bin for the dev scripts
# (install.sh); rpm relocates to /usr/bin. Patch the STAGED copies only.
sed -i 's|/usr/local/bin/|%{_bindir}/|g' \
    %{buildroot}%{_unitdir}/grepfocusd.service \
    %{buildroot}%{_datadir}/applications/grepfocus.desktop \
    %{buildroot}%{_sysconfdir}/xdg/autostart/grepfocus.desktop

install -D -m 0644 packaging/systemd/80-grepfocus.preset %{buildroot}%{_presetdir}/80-grepfocus.preset
install -D -m 0644 packaging/sysusers.d/grepfocus.conf %{buildroot}%{_sysusersdir}/grepfocus.conf
install -D -m 0644 packaging/tmpfiles.d/grepfocus.conf %{buildroot}%{_tmpfilesdir}/grepfocus.conf

install -D -m 0644 crates/gui/icons/icon.png %{buildroot}%{_datadir}/icons/hicolor/64x64/apps/grepfocus.png

install -d -m 0700 %{buildroot}%{_sysconfdir}/grepfocus
install -d -m 0700 %{buildroot}%{_sharedstatedir}/grepfocus

%post
# Enable per the packaged preset (80-grepfocus.preset) and register the unit.
%systemd_post grepfocusd.service
# Create /run/grepfocus now; tmpfiles.d otherwise only runs at boot.
systemd-tmpfiles --create grepfocus.conf || :
# Start on first install — a deliberate deviation from the packaging
# guidelines: a blocker daemon that isn't running is broken, and the
# preset + %%systemd_post only ENABLE the unit, they never start it.
if [ $1 -eq 1 ]; then
    systemctl start grepfocusd.service || :
fi

%preun
# Stop/disable FIRST: `grepfocusd cleanup` refuses while the unit is active.
%systemd_preun grepfocusd.service
# Erase only ($1 == 0), never on upgrade: tear down enforcement (immutable
# /etc/hosts bit, managed hosts region, nftables table, persisted blocks)
# while the binary still exists — removing it first would strand a
# chattr +i /etc/hosts.
# NEVER pass --purge here: rpm erase keeps /var/lib/grepfocus,
# /etc/grepfocus, and the grepfocus group. Purging saved data is a manual
# `grepfocusd cleanup --purge` before erasing the package.
if [ $1 -eq 0 ]; then
    timeout --kill-after=5 30 %{_bindir}/grepfocusd cleanup || :
fi

%postun
# Restart the daemon on upgrade (no-op on erase).
%systemd_postun_with_restart grepfocusd.service

%files
%license LICENSE
%doc README.md
%{_bindir}/grepfocusd
%{_bindir}/grepfocus-gui
%{_unitdir}/grepfocusd.service
%{_presetdir}/80-grepfocus.preset
%{_sysusersdir}/grepfocus.conf
%{_tmpfilesdir}/grepfocus.conf
%{_datadir}/applications/grepfocus.desktop
# The admin may customize or remove the autostart entry; keep it on upgrade.
%config(noreplace) %{_sysconfdir}/xdg/autostart/grepfocus.desktop
%{_datadir}/icons/hicolor/64x64/apps/grepfocus.png
# Directories owned for tracking; the runtime files inside are deliberately
# unowned so `rpm -e` keeps user data (saved blocks, password, secret).
%dir %attr(0700,root,root) %{_sysconfdir}/grepfocus
%dir %attr(0700,root,root) %{_sharedstatedir}/grepfocus

%changelog
* Sat Jul 18 2026 Bryan <bhshin@gmail.com> - 0.2.0-1
- Relicense to PolyForm Shield 1.0.0 (source-available, noncompete)
- Single binary: all premium features present, unlocked by a license key

* Sat Jul 11 2026 Bryan <bhshin@gmail.com> - 0.1.0-1
- Initial package
