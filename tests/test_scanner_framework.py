"""Regression tests for the new scanner framework."""

from __future__ import annotations

import asyncio
import tempfile
import os

import pytest

from src.triagekit.core.scanners import (
    ScannerOrchestrator,
    ScanContext,
    ScanType,
    Severity,
    UnifiedFinding,
    FindingDeduplicator,
    FindingCorrelator,
    CorrelationEngine,
    get_scanner_registry,
    register_all_scanners,
    StaticAnalysisScanner,
    HeuristicSecurityScanner,
    RepositoryScanner,
    DependencyScanner,
    WebScanner,
)


class TestScannerRegistry:
    """Tests for ScannerRegistry."""

    def setup_method(self):
        """Clear registry before each test."""
        registry = get_scanner_registry()
        registry.clear()

    def test_register_and_get(self):
        """Test registering and retrieving a scanner."""
        scanner = StaticAnalysisScanner()
        registry = get_scanner_registry()
        registry.register(scanner)

        assert registry.get("static_analysis") is scanner
        assert "static_analysis" in registry.list_names()

    def test_unregister(self):
        """Test unregistering a scanner."""
        scanner = StaticAnalysisScanner()
        registry = get_scanner_registry()
        registry.register(scanner)

        result = registry.unregister("static_analysis")
        assert result is True
        assert "static_analysis" not in registry.list_names()
        assert registry.get("static_analysis") is None

    def test_unregister_preserves_other_scanners(self):
        """Test unregistering one scanner doesn't affect others."""
        registry = get_scanner_registry()
        registry.register(StaticAnalysisScanner())
        registry.register(HeuristicSecurityScanner())

        registry.unregister("static_analysis")

        assert "static_analysis" not in registry.list_names()
        assert "heuristic_security" in registry.list_names()

    def test_get_by_type(self):
        """Test getting scanners by type."""
        registry = get_scanner_registry()
        registry.register(StaticAnalysisScanner())
        registry.register(HeuristicSecurityScanner())

        static_scanners = registry.get_by_type(ScanType.STATIC_ANALYSIS)
        heuristic_scanners = registry.get_by_type(ScanType.HEURISTIC_SECURITY)

        assert len(static_scanners) == 1
        assert static_scanners[0].name == "static_analysis"
        assert len(heuristic_scanners) == 1
        assert heuristic_scanners[0].name == "heuristic_security"

    def test_get_for_target(self):
        """Test filtering scanners by target."""
        registry = get_scanner_registry()
        registry.register(StaticAnalysisScanner())
        registry.register(RepositoryScanner())
        registry.register(WebScanner())

        # Local path should match repo and static
        path_scanners = registry.get_for_target("/some/path")
        names = [s.name for s in path_scanners]
        assert "repository_scanner" in names
        assert "static_analysis" in names

        # URL should match web scanner
        url_scanners = registry.get_for_target("https://example.com")
        names = [s.name for s in url_scanners]
        assert "web_scanner" in names


class TestRegistrySurvivesASecondScan:
    """D83: the repo scan worked exactly once per process.

    ``ScannerRegistry`` is a module-level global, but ``ScannerOrchestrator``
    keeps its ``_initialized`` flag per instance -- so a server process, which
    builds one orchestrator per request, called ``register_all_scanners`` on
    every request and the second one raised::

        ValueError: Scanner 'static_analysis' already registered

    The CLI never hit it because it scans once per process.  Three requests
    through the UI did.
    """

    def setup_method(self):
        get_scanner_registry().clear()

    def _register_all(self):
        register_all_scanners({"static_analysis": {}, "repository_scanner": {}})

    def test_registering_twice_does_not_raise(self):
        self._register_all()
        # This one line is the whole defect.
        self._register_all()
        assert "static_analysis" in get_scanner_registry().list_names()

    def test_repeated_register_does_not_duplicate_the_type_index(self):
        for _ in range(5):
            self._register_all()
        registry = get_scanner_registry()
        assert len(registry.list_names()) == len(set(registry.list_names()))
        for st in ScanType:
            listed = [n for n in registry.get_by_type(st)]
            assert len(listed) == len(set(listed)), (
                f"{st} index has duplicate names: {listed}"
            )

    def test_a_second_scan_gets_its_own_config(self):
        """Replacement is semantics, not just a workaround.

        A scanner binds its config to its instance, so the second request must
        be served by the instance it asked for -- not the one the first request
        registered, which is what silently ignoring the conflict would do.
        """
        register_all_scanners({"repository_scanner": {"max_files": 123}})
        first = get_scanner_registry().get("repository_scanner")
        assert first.config.get("max_files") == 123

        register_all_scanners({"repository_scanner": {"max_files": 456}})
        second = get_scanner_registry().get("repository_scanner")
        assert second.config.get("max_files") == 456
        assert second is not first

    def test_replace_false_still_refuses_a_duplicate(self):
        """The escape hatch must not become silent for callers that want it."""
        registry = get_scanner_registry()
        registry.register(StaticAnalysisScanner())
        with pytest.raises(ValueError):
            registry.register(StaticAnalysisScanner())

    def test_unregister_leaves_the_type_index_consistent(self):
        registry = get_scanner_registry()
        self._register_all()
        assert registry.unregister("static_analysis") is True
        assert "static_analysis" not in [
            s.name for s in registry.get_by_type(ScanType.STATIC_ANALYSIS)
        ]
        assert registry.get("static_analysis") is None
        # ...and an unknown name is False, not an exception.
        assert registry.unregister("nope") is False

    def test_concurrent_registration_does_not_deadlock_or_duplicate(self):
        """register() -> unregister() on the same RLock, from four threads."""
        import threading

        errors = []

        def worker(i):
            try:
                register_all_scanners(
                    {"repository_scanner": {"max_files": 100 + i},
                     "static_analysis": {}}
                )
            except Exception as e:  # pragma: no cover - surfaced below
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
        assert not any(t.is_alive() for t in threads), "registration deadlocked"
        assert errors == []
        registry = get_scanner_registry()
        assert len(registry.list_names()) == len(set(registry.list_names()))

    def test_shared_runner_works_twice_in_one_process(self):
        """The end-to-end symptom, not just the registry call that causes it.

        ``run_repo_scan`` builds a fresh ``ScannerOrchestrator`` per call, which
        is what the UI does per request.  Before D83 the first call succeeded and
        the second raised ``Scanner 'static_analysis' already registered``.
        """
        from pathlib import Path

        from triagekit.core.scan_runner import run_repo_scan

        corpus = Path(__file__).resolve().parent.parent / "dev" / "corpora" / "js_safe"
        if not corpus.is_dir():
            pytest.skip("dev/corpora/js_safe not present")

        runs = []
        for _ in range(2):
            run = run_repo_scan(str(corpus), no_cve=True, max_files=400)
            runs.append(len(run.legacy.findings))
            run.dispose()
        assert runs[0] == runs[1], f"scan results drifted: {runs}"
        assert runs[0] >= 1


class TestFindingDeduplicator:
    """Tests for FindingDeduplicator."""

    def test_exact_duplicates_merged(self):
        """Test that exact duplicates are merged."""
        f1 = UnifiedFinding(
            scanner_name='scanner1',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='SQL Injection in login.py',
            description='Possible SQL injection',
            severity=Severity.HIGH,
            category='sql-injection',
            file_path='src/auth/login.py',
            line_number=42,
        )

        f2 = UnifiedFinding(
            scanner_name='scanner1',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='SQL Injection in login.py',
            description='Possible SQL injection',
            severity=Severity.HIGH,
            category='sql-injection',
            file_path='src/auth/login.py',
            line_number=42,
        )

        dedup = FindingDeduplicator()
        results = dedup.deduplicate([f1, f2])

        assert len(results) == 1
        assert results[0].is_duplicate is False
        assert len(results[0].correlated_findings) == 1

    def test_different_findings_not_merged(self):
        """Test that different findings are not merged."""
        f1 = UnifiedFinding(
            scanner_name='scanner1',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='SQL Injection in login.py',
            description='Possible SQL injection',
            severity=Severity.HIGH,
            category='sql-injection',
            file_path='src/auth/login.py',
            line_number=42,
        )

        f2 = UnifiedFinding(
            scanner_name='scanner1',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='Command Injection in util.py',
            description='Possible command injection',
            severity=Severity.HIGH,
            category='command-injection',
            file_path='src/utils/util.py',
            line_number=15,
        )

        dedup = FindingDeduplicator()
        results = dedup.deduplicate([f1, f2])

        assert len(results) == 2

    def test_cross_scanner_same_location_not_merged(self):
        """Test that same finding from different scanners is not auto-merged (different fingerprint)."""
        f1 = UnifiedFinding(
            scanner_name='scanner1',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='SQL Injection in login.py',
            description='Possible SQL injection',
            severity=Severity.HIGH,
            category='sql-injection',
            file_path='src/auth/login.py',
            line_number=42,
        )

        f2 = UnifiedFinding(
            scanner_name='scanner2',
            scanner_version='1.0',
            scan_type=ScanType.HEURISTIC_SECURITY,
            title='SQL Injection in login.py',
            description='Possible SQL injection',
            severity=Severity.HIGH,
            category='sql-injection',
            file_path='src/auth/login.py',
            line_number=42,
        )

        dedup = FindingDeduplicator()
        results = dedup.deduplicate([f1, f2])

        # They should NOT be merged because fingerprints include scan_type
        assert len(results) == 2
        for r in results:
            assert r.is_duplicate is False


class TestFindingCorrelator:
    """Tests for FindingCorrelator."""

    def test_cwe_correlation(self):
        """Test that findings with same CWE are correlated."""
        f1 = UnifiedFinding(
            scanner_name='static_analysis',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='Unsafe Deserialization',
            description='Pickle usage',
            severity=Severity.CRITICAL,
            category='unsafe-deserialization',
            file_path='src/auth/login.py',
            line_number=42,
            cwe_ids=['CWE-502'],
        )

        f2 = UnifiedFinding(
            scanner_name='repository_scanner',
            scanner_version='1.0',
            scan_type=ScanType.REPOSITORY_SCAN,
            title='Unsafe Deserialization',
            description='Pickle usage',
            severity=Severity.CRITICAL,
            category='unsafe-deserialization',
            file_path='src/auth/login.py',
            line_number=42,
            cwe_ids=['CWE-502'],
        )

        engine = CorrelationEngine()
        from src.triagekit.core.scanners import ScanResult

        r1 = ScanResult(scanner_name='static', scanner_version='1', scan_type=ScanType.STATIC_ANALYSIS, target='test', findings=[f1])
        r2 = ScanResult(scanner_name='repo', scanner_version='1', scan_type=ScanType.REPOSITORY_SCAN, target='test', findings=[f2])

        result = engine.process([r1, r2])

        assert len(result["correlated_groups"]) == 1
        group = result["correlated_groups"][0]
        assert group.combined_severity == Severity.CRITICAL
        assert len(group.related_findings) == 1

    def test_different_cwe_not_correlated(self):
        """Test that findings with different CWEs are not correlated."""
        f1 = UnifiedFinding(
            scanner_name='static_analysis',
            scanner_version='1.0',
            scan_type=ScanType.STATIC_ANALYSIS,
            title='Unsafe Deserialization',
            description='Pickle usage',
            severity=Severity.CRITICAL,
            category='unsafe-deserialization',
            file_path='src/auth/login.py',
            line_number=42,
            cwe_ids=['CWE-502'],
        )

        f2 = UnifiedFinding(
            scanner_name='repository_scanner',
            scanner_version='1.0',
            scan_type=ScanType.REPOSITORY_SCAN,
            title='Command Injection',
            description='os.system usage',
            severity=Severity.HIGH,
            category='command-injection',
            file_path='src/auth/login.py',
            line_number=42,
            cwe_ids=['CWE-78'],
        )

        engine = CorrelationEngine()
        from src.triagekit.core.scanners import ScanResult

        r1 = ScanResult(scanner_name='static', scanner_version='1', scan_type=ScanType.STATIC_ANALYSIS, target='test', findings=[f1])
        r2 = ScanResult(scanner_name='repo', scanner_version='1', scan_type=ScanType.REPOSITORY_SCAN, target='test', findings=[f2])

        result = engine.process([r1, r2])

        # Should NOT be correlated - different CWEs
        assert len(result["correlated_groups"]) == 0


class TestScannerOrchestrator:
    """Tests for ScannerOrchestrator."""

    def setup_method(self):
        """Clear registry before each test."""
        registry = get_scanner_registry()
        registry.clear()

    @pytest.mark.asyncio
    async def test_orchestrator_runs_multiple_scanners(self):
        """Test that orchestrator runs multiple scanners."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, 'vuln.py')
            with open(vuln_file, 'w') as f:
                f.write('import os\nos.system("ls")\n')

            files_data = [
                {'filename': 'vuln.py', 'status': 'modified', 'additions': 10, 'deletions': 0,
                 'patch': '+os.system("ls")'},
            ]

            context = ScanContext(
                target=tmpdir,
                metadata={'files_data': files_data, 'manifest_files': []}
            )

            orchestrator = ScannerOrchestrator()
            orchestrator.initialize()

            result = await orchestrator.run_scan(tmpdir, context)

            assert result.summary["scanners_run"] >= 2
            assert result.summary["total_findings"] > 0
            assert "repository_scanner" in result.summary["by_scanner"]

    @pytest.mark.asyncio
    async def test_orchestrator_dry_run(self):
        """Test dry run mode."""
        with tempfile.TemporaryDirectory() as tmpdir:
            context = ScanContext(target=tmpdir, dry_run=True)

            orchestrator = ScannerOrchestrator()
            orchestrator.initialize()

            result = await orchestrator.run_scan(tmpdir, context)

            # All scanners should complete but with warnings
            for r in result.scan_results:
                assert r.status.value == "completed"
                assert len(r.warnings) > 0


class TestStaticAnalysisScanner:
    """Tests for StaticAnalysisScanner."""

    @pytest.mark.asyncio
    async def test_static_analysis_with_files(self):
        """Test static analysis with file data."""
        files_data = [
            {'filename': 'src/auth/login.py', 'status': 'modified', 'additions': 50, 'deletions': 10, 'patch': ''},
            {'filename': 'tests/test_auth.py', 'status': 'added', 'additions': 30, 'deletions': 0, 'patch': ''},
        ]

        context = ScanContext(
            target='pr:123',
            metadata={'files_data': files_data}
        )

        scanner = StaticAnalysisScanner()
        result = await scanner.scan(context)

        assert result.status.value == "completed"
        assert len(result.findings) > 0
        assert "static_score" in result.metadata


class TestHeuristicSecurityScanner:
    """Tests for HeuristicSecurityScanner."""

    @pytest.mark.asyncio
    async def test_heuristic_detects_sql_injection(self):
        """Test that heuristic scanner detects SQL injection patterns."""
        files_data = [
            {'filename': 'src/auth/login.py', 'status': 'modified', 'additions': 10, 'deletions': 0,
             'patch': '+query = f"SELECT * FROM users WHERE name={user}"'},
        ]

        context = ScanContext(
            target='pr:123',
            metadata={'files_data': files_data}
        )

        scanner = HeuristicSecurityScanner()
        result = await scanner.scan(context)

        assert result.status.value == "completed"
        # Should detect SQL injection
        sql_findings = [f for f in result.findings if 'sql' in f.category.lower()]
        assert len(sql_findings) > 0


class TestRepositoryScanner:
    """Tests for RepositoryScanner."""

    @pytest.mark.asyncio
    async def test_repo_scanner_finds_vulns(self):
        """Test repo scanner finds vulnerabilities in code."""
        with tempfile.TemporaryDirectory() as tmpdir:
            vuln_file = os.path.join(tmpdir, 'vuln.py')
            with open(vuln_file, 'w') as f:
                f.write('import os\nos.system("ls")\n')

            context = ScanContext(target=tmpdir)
            scanner = RepositoryScanner({'max_files': 10})
            result = await scanner.scan(context)

            assert result.status.value == "completed"
            assert len(result.findings) > 0


class TestDependencyScanner:
    """Tests for DependencyScanner."""

    @pytest.mark.asyncio
    async def test_dependency_scanner_finds_vulns(self):
        """Test dependency scanner finds known vulnerabilities."""
        with tempfile.TemporaryDirectory() as tmpdir:
            req_file = os.path.join(tmpdir, 'requirements.txt')
            with open(req_file, 'w') as f:
                f.write('requests==2.25.0\nflask==1.1.2\n')

            context = ScanContext(target=tmpdir)
            scanner = DependencyScanner({'max_packages': 10})
            result = await scanner.scan(context)

            assert result.status.value == "completed"
            # Should find known vulnerabilities in old packages
            assert len(result.findings) > 0


class TestBackwardCompatibility:
    """Tests to ensure existing analyzers still work unchanged."""

    def test_existing_static_analyzer(self):
        """Test that existing static analyzer functions work."""
        from src.triagekit.core.analyzers.static import analyze_files, compute_static_risk

        files_data = [
            {'filename': 'src/auth/login.py', 'status': 'modified', 'additions': 50, 'deletions': 10},
        ]

        insights = analyze_files(files_data)
        score, signals = compute_static_risk(insights, 50, 10, 1)

        assert isinstance(score, float)
        assert isinstance(signals, list)

    def test_existing_security_analyzer(self):
        """Test that existing security analyzer functions work."""
        from src.triagekit.core.analyzers.security import scan_diff_for_security

        files_data = [
            {'filename': 'src/auth/login.py', 'status': 'modified', 'additions': 10, 'deletions': 0,
             'patch': '+query = f"SELECT * FROM users WHERE name={user}"'},
        ]

        findings = scan_diff_for_security(files_data)
        assert isinstance(findings, list)
        assert len(findings) > 0

    def test_existing_repo_scanner(self):
        """Test that existing repo scanner works."""
        from src.triagekit.core.analyzers.repo_scan import scan_repository

        with tempfile.TemporaryDirectory() as tmpdir:
            with open(os.path.join(tmpdir, 'test.py'), 'w') as f:
                f.write('print("hello")\n')
            result = scan_repository(tmpdir, max_files=10)

            assert isinstance(result.files_scanned, int)
            assert hasattr(result, 'score')

    def test_existing_web_scanner(self):
        """Test that existing web scanner types work."""
        from src.triagekit.core.analyzers.web_scan import WebScanResult, WebFinding

        result = WebScanResult(url="https://example.com")
        assert result.url == "https://example.com"

        finding = WebFinding(
            severity="high",
            category="test",
            title="Test",
            detail="Test detail",
            recommendation="Fix it",
        )
        assert finding.severity == "high"

    def test_existing_cve_scanner(self):
        """Test that existing CVE scanner functions work."""
        from src.triagekit.core.analyzers.cve import query_osv

        # This makes a network call, so just test the function exists
        assert callable(query_osv)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])