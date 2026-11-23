"""Lockfile readers for pnpm, uv, Composer, NuGet, Gradle and Maven, plus the notes for manifests without a lockfile"""
import sys

import pytest

from services import dependency_check as dc


def parsed(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return {(e, n, v) for e, n, v, _, _ in dc.parse_lockfile(str(path), text)}


PNPM_V5 = """lockfileVersion: 5.4

specifiers:
  react-dom: ^17.0.2

dependencies:
  react-dom: 17.0.2_react@17.0.2

packages:

  /react-dom/17.0.2_react@17.0.2:
    resolution: {integrity: sha512-x}
    dependencies:
      react: 17.0.2

  /@babel/core/7.12.3:
    resolution: {integrity: sha512-y}

  /lodash/4.17.20:
    resolution: {integrity: sha512-z}
"""

PNPM_V6 = """lockfileVersion: '6.0'

dependencies:
  react-dom:
    specifier: ^17.0.2
    version: 17.0.2(react@17.0.2)

packages:

  /react-dom@17.0.2(react@17.0.2):
    resolution: {integrity: sha512-x}

  /@babel/core@7.12.3:
    resolution: {integrity: sha512-y}
"""

PNPM_V9 = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.20
        version: 4.17.20

packages:

  '@babel/core@7.12.3':
    resolution: {integrity: sha512-y}

  lodash@4.17.20:
    resolution: {integrity: sha512-z}

  my-tool@https://codeload.github.com/me/tool/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/me/tool/tar.gz/abc}

snapshots:

  '@babel/core@7.12.3':
    dependencies:
      lodash: 4.17.20

  lodash@4.17.20: {}
"""


def test_pnpm_lockfile_versions(tmp_path):
    assert parsed(tmp_path, "pnpm-lock.yaml", PNPM_V5) == {
        ("npm", "react-dom", "17.0.2"), ("npm", "@babel/core", "7.12.3"), ("npm", "lodash", "4.17.20")}
    assert parsed(tmp_path, "pnpm-lock.yaml", PNPM_V6) == {
        ("npm", "react-dom", "17.0.2"), ("npm", "@babel/core", "7.12.3")}
    # git/tarball packages are skipped; snapshots repeat packages and aren't read twice
    assert parsed(tmp_path, "pnpm-lock.yaml", PNPM_V9) == {
        ("npm", "@babel/core", "7.12.3"), ("npm", "lodash", "4.17.20")}


@pytest.mark.skipif(sys.version_info < (3, 11), reason="TOML lockfiles need Python 3.11+")
def test_uv_lock_skips_the_project_itself(tmp_path):
    text = """version = 1
requires-python = ">=3.11"

[[package]]
name = "myapp"
version = "0.1.0"
source = { editable = "." }

[[package]]
name = "requests"
version = "2.19.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "localpkg"
version = "1.0.0"
source = { directory = "../localpkg" }
"""
    assert parsed(tmp_path, "uv.lock", text) == {("PyPI", "requests", "2.19.0")}


@pytest.mark.skipif(sys.version_info < (3, 11), reason="TOML lockfiles need Python 3.11+")
def test_cargo_workspace_crates_are_skipped(tmp_path):
    text = """version = 3

[[package]]
name = "my-crate"
version = "0.1.0"

[[package]]
name = "smallvec"
version = "1.6.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"""
    assert parsed(tmp_path, "Cargo.lock", text) == {("crates.io", "smallvec", "1.6.0")}


def test_composer_lock(tmp_path):
    text = """{
    "packages": [
        {"name": "guzzlehttp/guzzle", "version": "7.4.4"},
        {"name": "symfony/http-kernel", "version": "v5.4.1"},
        {"name": "acme/internal", "version": "dev-main"}
    ],
    "packages-dev": [
        {"name": "phpunit/phpunit", "version": "9.5.0"}
    ]
}"""
    assert parsed(tmp_path, "composer.lock", text) == {
        ("Packagist", "guzzlehttp/guzzle", "7.4.4"), ("Packagist", "symfony/http-kernel", "5.4.1"),
        ("Packagist", "phpunit/phpunit", "9.5.0")}


def test_nuget_lockfile_and_project_files(tmp_path):
    lock = """{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"},
      "System.Text.Encodings.Web": {"type": "Transitive", "resolved": "4.5.0"},
      "MyLib": {"type": "Project"}
    },
    "net6.0": {
      "Newtonsoft.Json": {"type": "Direct", "requested": "[12.0.1, )", "resolved": "12.0.1"}
    }
  }
}"""
    assert parsed(tmp_path, "packages.lock.json", lock) == {
        ("NuGet", "Newtonsoft.Json", "12.0.1"), ("NuGet", "System.Text.Encodings.Web", "4.5.0")}

    csproj = """<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Serilog">
      <Version>2.10.0</Version>
    </PackageReference>
    <PackageReference Include="Floating" Version="1.*" />
    <PackageReference Include="Ranged" Version="[1.0,2.0)" />
    <PackageReference Include="Central" />
  </ItemGroup>
</Project>"""
    assert parsed(tmp_path, "App.csproj", csproj) == {
        ("NuGet", "Newtonsoft.Json", "12.0.1"), ("NuGet", "Serilog", "2.10.0")}

    props = """<Project>
  <ItemGroup>
    <PackageVersion Include="Central" Version="3.1.0" />
  </ItemGroup>
</Project>"""
    assert parsed(tmp_path, "Directory.Packages.props", props) == {("NuGet", "Central", "3.1.0")}


def test_gradle_lockfile(tmp_path):
    text = """# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
com.fasterxml.jackson.core:jackson-databind:2.9.8=compileClasspath,runtimeClasspath
org.apache.logging.log4j:log4j-core:2.14.1=runtimeClasspath
empty=annotationProcessor
"""
    assert parsed(tmp_path, "gradle.lockfile", text) == {
        ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")}


POM = """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>demo</artifactId>
  <version>1.0.0</version>
  <properties>
    <log4j.version>2.14.1</log4j.version>
    <jackson.base>2.9</jackson.base>
    <jackson.version>${jackson.base}.8</jackson.version>
  </properties>
  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>2.5.0</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.apache.logging.log4j</groupId>
      <artifactId>log4j-core</artifactId>
      <version>${log4j.version}</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>${jackson.version}</version>
    </dependency>
    <dependency>
      <groupId>com.example</groupId>
      <artifactId>sibling</artifactId>
      <version>${project.version}</version>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${undefined.version}</version>
    </dependency>
  </dependencies>
</project>"""


def test_maven_pom(tmp_path):
    path = tmp_path / "pom.xml"
    path.write_text(POM, encoding="utf-8")
    found = dc.parse_lockfile(str(path), POM)
    assert {(e, n, v) for e, n, v, _, _ in found} == {
        ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1"),
        ("Maven", "com.fasterxml.jackson.core:jackson-databind", "2.9.8"),
        ("Maven", "com.example:sibling", "1.0.0")}
    lines = POM.splitlines()
    for _, name, _, _, line in found:
        assert f"<artifactId>{name.split(':')[1]}</artifactId>" in lines[line - 1]


def test_broken_files_are_skipped_not_raised(tmp_path):
    assert parsed(tmp_path, "pom.xml", "<project><dependencies>") == set()
    assert parsed(tmp_path, "App.csproj", "not xml") == set()
    assert parsed(tmp_path, "composer.lock", "{") == set()


def test_new_formats_are_found_and_manifests_get_notes(tmp_path):
    (tmp_path / "api").mkdir()
    (tmp_path / "api" / "pom.xml").write_text(POM, encoding="utf-8")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "App.csproj").write_text(
        '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="12.0.1" /></ItemGroup></Project>',
        encoding="utf-8")
    (tmp_path / "locked").mkdir()
    (tmp_path / "locked" / "Lib.csproj").write_text('<Project />', encoding="utf-8")
    (tmp_path / "locked" / "packages.lock.json").write_text('{"dependencies": {}}', encoding="utf-8")
    (tmp_path / "pnpm-lock.yaml").write_text(PNPM_V9, encoding="utf-8")

    found = {p.replace("\\", "/").split("/")[-1] for p in dc.find_lockfiles(str(tmp_path))}
    assert found == {"pom.xml", "App.csproj", "Lib.csproj", "packages.lock.json", "pnpm-lock.yaml"}

    class NoVulns:
        def vulnerable(self, packages):
            return {}

    data = dc.check_dependencies(str(tmp_path), client=NoVulns())
    assert data["packages"] == 3 + 1 + 2  # pom, csproj, pnpm
    notes = " ".join(data["notes"])
    assert "pom.xml" in notes and "Maven has no lockfile" in notes
    assert "App.csproj" in notes and "RestorePackagesWithLockFile" in notes
    assert "Lib.csproj" not in notes  # it has a packages.lock.json next to it
