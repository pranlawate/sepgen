# Implementation Plan: RPM Packaging for SELinux Tool Suite

**Date:** 2026-03-22
**Goal:** Create RPM spec files for sepgen, semacro, and avc-parser so
users can install with `dnf install sepgen semacro avc-parser`.

---

## Context

All three tools currently require `pip install` or manual setup. Regular
sysadmins expect `dnf install` and `/usr/bin/` entry points. Each tool
is an independent upstream project with its own repo, but they work
together as a suite for SELinux policy development.

## Architecture Decision

**Three separate RPMs** — matches Fedora packaging guidelines (one RPM
per upstream project). sepgen has soft dependencies on the other two:

```
sepgen (Recommends: semacro, avc-parser)
    ├── /usr/bin/sepgen
    ├── Requires: python3 >= 3.9, strace, selinux-policy-devel
    └── Recommends: semacro, avc-parser

semacro (standalone)
    ├── /usr/bin/semacro
    ├── Requires: python3 >= 3.9, selinux-policy-devel
    └── bash-completion

avc-parser (standalone)
    ├── /usr/bin/avc-parser
    ├── Requires: python3 >= 3.9, python3-rich
    └── Requires: policycoreutils (for ausearch)
```

## Phase 1: Fix Entry Points (pip install creates /usr/bin/)

### Step 1: sepgen entry point
- **File:** `pyproject.toml` — already has `[project.scripts] sepgen = "sepgen.__main__:main"`
- **Fix:** `sepgen/__main__.py` needs to expose `main()` properly
- **Verify:** `pip install -e .` creates `/usr/local/bin/sepgen`

### Step 2: avc-parser entry point
- **File:** `pyproject.toml` — add `[project.scripts] avc-parser = "parse_avc:main"`
- **Or:** For RPM, just install `parse_avc.py` as `/usr/bin/avc-parser` directly
- **Note:** avc-parser has supporting modules (formatters/, selinux/, validators/)
  that need to be installed alongside

### Step 3: semacro entry point
- Already a standalone script, `semacro.spec` handles installation
- Verify: `%install` section copies to `%{_bindir}/semacro`

## Phase 2: Create RPM Spec Files

### Step 4: semacro.spec (verify existing)
- **File:** Already exists at `semacro/semacro.spec`
- Verify it builds: `rpmbuild -ba semacro.spec`
- Verify `/usr/bin/semacro` works after install
- Verify bash-completion installs
- Verify man page installs

### Step 5: avc-parser.spec (create new)
- **New file:** `avc-parser/avc-parser.spec`

```spec
Name:           avc-parser
Version:        1.8.1
Release:        1%{?dist}
Summary:        SELinux AVC denial parser and analyzer
License:        MIT
URL:            https://github.com/pranlawate/avc-parser
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
Requires:       python3 >= 3.9
Requires:       python3-rich
Requires:       policycoreutils

%description
Parses SELinux AVC denial messages from audit logs with extended audit
record support. Provides structured analysis, deduplication, and
multiple output formats including JSON and sealert-style reports.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{python3_sitelib}/avc_parser
install -m 755 parse_avc.py %{buildroot}%{_bindir}/avc-parser
# Install supporting modules
cp -r formatters/ selinux/ validators/ utils/ \
    %{buildroot}%{python3_sitelib}/avc_parser/

%files
%{_bindir}/avc-parser
%{python3_sitelib}/avc_parser/
%license LICENSE
%doc README.md
```

### Step 6: sepgen.spec (create new)
- **New file:** `sepgen/sepgen.spec`

```spec
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
Requires:       python3 >= 3.9
Requires:       strace
Requires:       selinux-policy-devel
Recommends:     semacro
Recommends:     avc-parser

%description
SELinux policy generator that analyzes C/C++/Python source code and
traces runtime behavior to produce macro-based policy modules with
custom types. Supports three-phase workflow: analyze (static),
trace (runtime), refine (denial-driven).

%prep
%autosetup

%build
%pyproject_wheel

%install
%pyproject_install

%files
%{_bindir}/sepgen
%{python3_sitelib}/sepgen/
%{python3_sitelib}/sepgen-*.dist-info/
%license LICENSE
%doc README.md
```

## Phase 3: Build and Test

### Step 7: Create source tarballs
- `git archive --prefix=semacro-0.2.0/ -o semacro-0.2.0.tar.gz HEAD`
- `git archive --prefix=avc-parser-1.8.1/ -o avc-parser-1.8.1.tar.gz HEAD`
- `git archive --prefix=sepgen-0.1.0/ -o sepgen-0.1.0.tar.gz HEAD`
- Place in `~/rpmbuild/SOURCES/`

### Step 8: Build RPMs
- `rpmbuild -ba semacro.spec`
- `rpmbuild -ba avc-parser.spec`
- `rpmbuild -ba sepgen.spec`
- Fix any build errors

### Step 9: Install and test on VM
- `dnf install ./semacro-*.rpm ./avc-parser-*.rpm ./sepgen-*.rpm`
- Verify: `semacro --help`, `avc-parser --help`, `sepgen --help`
- Verify: `sepgen analyze`, `sepgen trace`, `sepgen refine` all work
- Verify: refine finds semacro and avc-parser in PATH

## Phase 4: COPR Distribution (optional, after local RPM works)

### Step 9b: Set up COPR project
- Create COPR project: `pranlawate/selinux-tools`
- Upload .src.rpm files or connect to GitHub repos
- Enable builds for Fedora 42, 43, and EPEL 9
- Users install with: `dnf copr enable pranlawate/selinux-tools`

### Step 9c: Verify COPR install
- Test on clean VM: `dnf copr enable pranlawate/selinux-tools`
- `dnf install sepgen` (pulls semacro + avc-parser via Recommends)
- Verify complete workflow works

## Phase 5: Confine the Tools

### Step 10: Confine semacro
- `sepgen analyze` on semacro source (Python)
- `sepgen trace semacro which ntpd_t ...` on VM
- `sepgen refine` after enforcing mode test
- Expected: seutil_read_config, files_read_usr_files

### Step 11: Confine avc-parser
- `sepgen analyze` on avc-parser source (Python)
- `sepgen trace avc-parser --file /var/log/audit/audit.log` on VM
- `sepgen refine` after enforcing mode test
- Expected: logging_read_all_logs, auth_use_nsswitch

### Step 12: Confine snapm
- `sepgen analyze` on snapm source (Python)
- `sepgen trace snapm snapset list` on VM
- `sepgen refine` after enforcing mode test
- Target: full working snapm policy

## Execution Order

1. Steps 1-3 (entry points — quick fixes)
2. Steps 4-6 (spec files — main work)
3. Steps 7-9 (build and test on VM)
4. Steps 10-12 (confine the tools — proves the whole workflow)
