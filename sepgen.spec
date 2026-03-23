Name:           sepgen
Version:        0.1.0
Release:        1%{?dist}
Summary:        SELinux policy generator from source code and runtime tracing

License:        MIT
URL:            https://github.com/pranlawate/sepgen
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip
BuildRequires:  python3-wheel
Requires:       python3 >= 3.9
Requires:       strace
Requires:       selinux-policy-devel
Requires:       policycoreutils-devel
Recommends:     semacro
Recommends:     avc-parser

%description
SELinux policy generator that analyzes C/C++/Python source code and
traces runtime behavior to produce macro-based policy modules with
custom types. Supports three-phase workflow:

  sepgen analyze  - generate policy from source code (C/C++/Python)
  sepgen trace    - observe runtime behavior with strace
  sepgen refine   - read AVC denials and suggest macro additions

Works with semacro (macro explorer) and avc-parser (denial analyzer)
for a complete SELinux policy development workflow.

%prep
%autosetup

%build
%pyproject_wheel

%install
%pyproject_install
install -Dm644 completions/sepgen.bash \
    %{buildroot}%{_datadir}/bash-completion/completions/sepgen
install -Dm644 completions/sepgen.zsh \
    %{buildroot}%{_datadir}/zsh/site-functions/_sepgen

%files
%license LICENSE
%doc README.md
%{_bindir}/sepgen
%{python3_sitelib}/sepgen/
%{python3_sitelib}/sepgen-%{version}.dist-info/
%{_datadir}/bash-completion/completions/sepgen
%{_datadir}/zsh/site-functions/_sepgen

%changelog
* Sun Mar 22 2026 Pranav Lawate <pran.lawate@gmail.com> - 0.1.0-1
- Initial RPM packaging
- Static analysis: C/C++ (regex), Python (AST), 26 classification rules
- Runtime tracing: strace with --secontext, FD tracking, 15 syscall patterns
- Policy refinement: avc-parser + semacro integration
- Proven: earlyoom confined as earlyoom_t with zero AVCs
- Validated against 11 test applications
