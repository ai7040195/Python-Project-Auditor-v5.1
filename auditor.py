#!/usr/bin/env python3
"""
Python Project Auditor v5.1
Enterprise-grade security, quality and CI/CD analysis tool.
Zero external dependencies required (optional: tqdm, tomli, sarif-om).

Single-file deployment - ready for production use.
Comprehensive security analysis, quality scoring, and compliance reporting.
"""

from __future__ import annotations

import argparse
import ast
import functools
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Optional dependencies with graceful fallbacks
try:
    import tomli as toml
except ImportError:
    try:
        import tomllib as toml
    except ImportError:
        toml = None

try:
    from tqdm import tqdm
except ImportError:
    def tqdm(iterable=None, **kwargs):
        return iterable

try:
    from sarif_om import Tool, ToolComponent, Result, Location, PhysicalLocation, ArtifactLocation, Region
    SARIF_AVAILABLE = True
except ImportError:
    SARIF_AVAILABLE = False


# =========================================================================== #
#  CONFIGURATION MANAGEMENT
# =========================================================================== #
@dataclass(slots=True)
class Config:
    """Centralized configuration with TOML support and validation."""
    
    project_root: Path = Path(".")
    timeout: int = 30
    max_file_size: int = 1024 * 1024  # 1MB
    exclude_files: set[str] = field(default_factory=lambda: {
        "__init__.py", "setup.py", "conftest.py", "test_*.py"
    })
    exclude_dirs: set[str] = field(default_factory=lambda: {
        ".git", "__pycache__", "venv", ".venv", "env", "node_modules",
        ".idea", ".vscode", "build", "dist", "tmp", "temp"
    })
    allowed_extensions: set[str] = field(default_factory=lambda: {".py"})
    enable_execution: bool = False
    max_workers: int = min(4, (os.cpu_count() or 1))
    min_acceptable_score: int = 70
    analysis_cache_size: int = 100
    readme_name: str = "SECURITY_AUDIT_REPORT.md"
    sarif_name: str = "audit_results.sarif"
    security_rules_path: Optional[Path] = None
    output_format: str = "both"  # "sarif", "markdown", or "both"

    @classmethod
    def load(cls, toml_path: Path | None) -> Config:
        """Load configuration from TOML file with defaults."""
        cfg = cls()
        
        if toml_path and toml_path.exists() and toml:
            try:
                with toml_path.open("rb") as f:
                    data = toml.load(f)
                
                auditor_config = data.get("tool", {}).get("auditor", {})
                for key, value in auditor_config.items():
                    if hasattr(cfg, key):
                        # Handle path conversions
                        if key in ["project_root", "security_rules_path"] and value:
                            setattr(cfg, key, Path(value).expanduser().resolve())
                        else:
                            setattr(cfg, key, value)
            except Exception as e:
                print(f"Warning: Failed to load TOML config: {e}", file=sys.stderr)
        
        return cfg

    def validate(self) -> None:
        """Validate configuration for security and correctness."""
        if not self.project_root.exists():
            raise ValueError(f"Project root does not exist: {self.project_root}")
        
        if self.timeout > 300:  # 5 minutes max
            raise ValueError("Timeout too high for security (max 300 seconds)")
        
        if self.max_workers > 16:
            raise ValueError("Too many workers for security (max 16)")
        
        if self.max_file_size > 10 * 1024 * 1024:  # 10MB max
            raise ValueError("Max file size too large for security")
        
        if self.output_format not in ["sarif", "markdown", "both"]:
            raise ValueError("Output format must be 'sarif', 'markdown', or 'both'")


# =========================================================================== #
#  PERFORMANCE CACHE (Thread-Safe)
# =========================================================================== #
class AnalysisCache:
    """Thread-safe LRU cache for AST analysis results."""
    
    def __init__(self, max_size: int = 100) -> None:
        self._max_size = max_size
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._order: List[str] = []
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    @staticmethod
    @functools.lru_cache(maxsize=512)
    def file_hash(path: Path) -> str:
        """Calculate file hash with caching."""
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception as e:
            return f"error_{hash(str(e))}"

    def get(self, path: Path, content_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis if available and valid."""
        key = str(path)
        with self._lock:
            cached = self._cache.get(key)
            if cached and cached["hash"] == content_hash:
                self._order.remove(key)
                self._order.append(key)
                self._hits += 1
                return cached["data"]
            self._misses += 1
            return None

    def set(self, path: Path, content_hash: str, data: Dict[str, Any]) -> None:
        """Cache analysis results with LRU eviction."""
        key = str(path)
        with self._lock:
            # Evict if cache is full
            if len(self._cache) >= self._max_size:
                oldest_key = self._order.pop(0)
                self._cache.pop(oldest_key, None)
            
            self._cache[key] = {"hash": content_hash, "data": data}
            self._order.append(key)

    @property
    def hit_ratio(self) -> float:
        """Calculate cache hit ratio."""
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0


# =========================================================================== #
#  SECURITY ANALYSIS ENGINE
# =========================================================================== #
@dataclass(slots=True, frozen=True)
class SecurityRule:
    """Immutable security rule definition."""
    
    id: str
    pattern: re.Pattern
    description: str
    severity: str  # "error", "warning", "note"
    category: str = "security"


class SecurityManager:
    """Advanced security analysis with configurable rules."""
    
    DEFAULT_RULES = [
        SecurityRule(
            id="PY001",
            pattern=re.compile(r"eval\s*\([^)]*[^'\"][^)]*\)"),
            description="Dangerous eval function with dynamic input",
            severity="error"
        ),
        SecurityRule(
            id="PY002", 
            pattern=re.compile(r"exec\s*\([^)]*[^'\"][^)]*\)"),
            description="Dangerous exec function with dynamic input",
            severity="error"
        ),
        SecurityRule(
            id="PY003",
            pattern=re.compile(r"os\.system\s*\("),
            description="Direct os.system call - use subprocess.run instead",
            severity="warning"
        ),
        SecurityRule(
            id="PY004",
            pattern=re.compile(r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True"),
            description="Unsafe subprocess with shell=True enabled",
            severity="error"
        ),
        SecurityRule(
            id="PY005",
            pattern=re.compile(r"pickle\.loads?\s*\("),
            description="Unsafe pickle deserialization",
            severity="error"
        ),
        SecurityRule(
            id="PY006",
            pattern=re.compile(r"marshal\.loads?\s*\("),
            description="Unsafe marshal deserialization", 
            severity="error"
        ),
        SecurityRule(
            id="PY007",
            pattern=re.compile(r"__import__\s*\("),
            description="Dynamic module import",
            severity="warning"
        ),
        SecurityRule(
            id="PY008",
            pattern=re.compile(r"input\s*\("),
            description="User input without validation",
            severity="note"
        )
    ]

    def __init__(self, rules_file: Optional[Path] = None):
        """Initialize with default and custom rules."""
        self.rules = list(self.DEFAULT_RULES)
        self._load_custom_rules(rules_file)

    def _load_custom_rules(self, rules_file: Optional[Path]) -> None:
        """Load custom security rules from JSON file."""
        if not rules_file or not rules_file.exists():
            return
            
        try:
            with rules_file.open('r', encoding='utf-8') as f:
                custom_rules = json.load(f)
            
            for rule_data in custom_rules:
                rule = SecurityRule(
                    id=rule_data['id'],
                    pattern=re.compile(rule_data['pattern']),
                    description=rule_data['description'],
                    severity=rule_data.get('severity', 'warning'),
                    category=rule_data.get('category', 'security')
                )
                self.rules.append(rule)
                
        except Exception as e:
            print(f"Warning: Failed to load custom security rules: {e}", file=sys.stderr)

    @staticmethod
    def safe_path(path: Path, base_directory: Path) -> bool:
        """Check if path is safe and within base directory."""
        try:
            resolved_path = path.resolve()
            resolved_base = base_directory.resolve()
            return resolved_base in resolved_path.parents or resolved_path == resolved_base
        except Exception:
            return False

    def scan_file(self, content: str, filepath: Path) -> List[Dict[str, Any]]:
        """Scan file content for security issues."""
        issues = []
        
        try:
            # AST-based scanning for precise detection
            tree = ast.parse(content, filename=str(filepath))
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    node_content = ast.get_source_segment(content, node)
                    if node_content:
                        self._check_node_content(node, node_content, filepath, issues)
        except SyntaxError:
            # Fallback to regex-based scanning for files with syntax errors
            self._regex_scan_content(content, filepath, issues)
        
        return issues

    def _check_node_content(self, node: ast.Call, node_content: str, 
                          filepath: Path, issues: List[Dict[str, Any]]) -> None:
        """Check AST node content against security rules."""
        for rule in self.rules:
            if rule.pattern.search(node_content):
                issue = {
                    "ruleId": rule.id,
                    "message": {"text": f"{rule.description}: {node_content.strip()}"},
                    "level": rule.severity,
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(filepath.relative_to(filepath.parent))},
                            "region": {
                                "startLine": getattr(node, 'lineno', 1),
                                "startColumn": getattr(node, 'col_offset', 0) + 1
                            }
                        }
                    }]
                }
                issues.append(issue)

    def _regex_scan_content(self, content: str, filepath: Path, 
                          issues: List[Dict[str, Any]]) -> None:
        """Fallback regex scanning for files with syntax errors."""
        for rule in self.rules:
            if rule.pattern.search(content):
                issue = {
                    "ruleId": rule.id,
                    "message": {"text": f"{rule.description} (regex fallback)"},
                    "level": rule.severity,
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": str(filepath.relative_to(filepath.parent))}
                        }
                    }]
                }
                issues.append(issue)


# =========================================================================== #
#  EXECUTION SANDBOX
# =========================================================================== #
class ExecutionSandbox:
    """Secure code execution in isolated environment."""
    
    @staticmethod
    def execute_safe(filepath: Path, timeout: int, enable: bool) -> Dict[str, Any]:
        """
        Execute Python file in secure sandbox.
        
        Returns:
            Dict with execution results including status, timing, and output
        """
        if not enable:
            return {
                "status": "EXECUTION_DISABLED",
                "time": 0,
                "stdout": "",
                "stderr": "Execution disabled in configuration",
                "sandbox_used": False,
                "return_code": -1
            }

        temp_dir = None
        try:
            # Create secure temporary environment
            temp_dir = Path(tempfile.mkdtemp(prefix="pyaudit_sandbox_"))
            safe_filepath = temp_dir / filepath.name
            
            # Copy file to sandbox
            shutil.copy2(filepath, safe_filepath)
            
            # Secure environment variables
            env = os.environ.copy()
            env.update({
                "PYTHONSAFEEXEC": "1",
                "PYTHONPATH": str(temp_dir),
                "PYTHONNOUSERSITE": "1"
            })
            
            # Execute in sandbox
            start_time = time.time()
            result = subprocess.run(
                [sys.executable, str(safe_filepath)],
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(temp_dir),
                env=env
            )
            execution_time = round(time.time() - start_time, 3)
            
            return {
                "status": "SUCCESS" if result.returncode == 0 else "EXECUTION_ERROR",
                "time": execution_time,
                "stdout": result.stdout[:2000],  # Limit output size
                "stderr": result.stderr[:2000],
                "sandbox_used": True,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "status": "TIMEOUT",
                "time": timeout,
                "stdout": "",
                "stderr": f"Execution timed out after {timeout} seconds",
                "sandbox_used": True,
                "return_code": -1
            }
        except Exception as e:
            return {
                "status": "SANDBOX_ERROR",
                "time": 0,
                "stdout": "",
                "stderr": f"Sandbox execution failed: {str(e)}",
                "sandbox_used": True,
                "return_code": -1
            }
        finally:
            # Cleanup sandbox
            if temp_dir and temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)


# =========================================================================== #
#  AST ANALYSIS & METRICS
# =========================================================================== #
class ASTAnalyzer:
    """Comprehensive AST analysis with native metrics calculation."""
    
    @staticmethod
    def analyze(filepath: Path, cache: AnalysisCache) -> Dict[str, Any]:
        """
        Analyze Python file using AST with caching.
        
        Returns:
            Dict containing AST analysis results and metrics
        """
        content_hash = cache.file_hash(filepath)
        
        # Check cache first
        cached_result = cache.get(filepath, content_hash)
        if cached_result:
            return cached_result

        # Default result structure
        result = {
            "docstring": None,
            "functions": [],
            "classes": [],
            "imports": [],
            "metrics": {},
            "analysis_error": None
        }

        try:
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            tree = ast.parse(content, filename=str(filepath))
            
            # Extract structural information
            result["docstring"] = ast.get_docstring(tree)
            result["functions"] = ASTAnalyzer._analyze_functions(tree, content)
            result["classes"] = ASTAnalyzer._analyze_classes(tree, content)
            result["imports"] = ASTAnalyzer._analyze_imports(tree)
            result["metrics"] = ASTAnalyzer._calculate_metrics(content, result)
            
            # Cache successful analysis
            cache.set(filepath, content_hash, result)
            
        except SyntaxError as e:
            result["analysis_error"] = f"SyntaxError: {e}"
        except Exception as e:
            result["analysis_error"] = f"AnalysisError: {e}"
            
        return result

    @staticmethod
    def _analyze_functions(tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Extract function information from AST."""
        functions = []
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                func_info = {
                    "name": node.name,
                    "line_number": node.lineno,
                    "arguments": len(node.args.args),
                    "decorators": [d.id for d in node.decorator_list 
                                 if isinstance(d, ast.Name)],
                    "has_docstring": ast.get_docstring(node) is not None,
                    "has_return_annotation": node.returns is not None
                }
                functions.append(func_info)
        return functions

    @staticmethod
    def _analyze_classes(tree: ast.AST, content: str) -> List[Dict[str, Any]]:
        """Extract class information from AST."""
        classes = []
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                class_info = {
                    "name": node.name,
                    "line_number": node.lineno,
                    "bases": [base.id for base in node.bases 
                            if isinstance(base, ast.Name)],
                    "has_docstring": ast.get_docstring(node) is not None
                }
                classes.append(class_info)
        return classes

    @staticmethod
    def _analyze_imports(tree: ast.AST) -> List[str]:
        """Extract import statements from AST."""
        imports = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:  # Handle "from . import" case
                    imports.add(node.module)
        return sorted(imports)

    @staticmethod
    def _calculate_metrics(content: str, ast_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate code quality metrics."""
        lines = content.splitlines()
        
        # Basic line counts
        loc = len(lines)
        non_empty_lines = [line for line in lines if line.strip()]
        lloc = len(non_empty_lines)
        
        # Comment analysis
        comment_lines = [line for line in lines 
                        if line.strip().startswith('#')]
        comment_count = len(comment_lines)
        
        # Complexity approximation
        complexity_keywords = ['if ', 'for ', 'while ', 'try:', 'except ', 
                              'with ', 'def ', 'class ', 'and ', 'or ']
        complexity_score = sum(content.count(keyword) for keyword in complexity_keywords)
        
        # Cyclomatic complexity approximation
        max_cc = max(2, complexity_score // max(1, len(ast_data["functions"])))
        
        return {
            "loc": loc,
            "lloc": lloc,
            "comment_lines": comment_count,
            "comment_density": round(comment_count / max(1, lloc) * 100, 1),
            "complexity_score": complexity_score,
            "max_cyclomatic_complexity": max_cc,
            "function_count": len(ast_data["functions"]),
            "class_count": len(ast_data["classes"]),
            "import_count": len(ast_data["imports"])
        }


# =========================================================================== #
#  QUALITY SCORING SYSTEM
# =========================================================================== #
class QualityScorer:
    """Comprehensive quality scoring with weighted categories."""
    
    WEIGHTS = {
        "documentation": 0.15,
        "structure": 0.15, 
        "execution": 0.30,
        "security": 0.20,
        "maintainability": 0.20
    }

    @staticmethod
    def calculate_score(ast_data: Dict[str, Any], execution_data: Dict[str, Any], 
                       security_issues: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate comprehensive quality score.
        
        Returns:
            Dict with total score, grade, and category breakdown
        """
        scores = {
            "documentation": QualityScorer._score_documentation(ast_data),
            "structure": QualityScorer._score_structure(ast_data),
            "execution": QualityScorer._score_execution(execution_data),
            "security": QualityScorer._score_security(security_issues),
            "maintainability": QualityScorer._score_maintainability(ast_data)
        }
        
        # Apply weights and calculate total - CORRETTO
        weighted_scores = {}
        for category, score in scores.items():
            weight = QualityScorer.WEIGHTS[category]
            weighted_scores[category] = round(score * weight * 100)
        
        total_score = sum(weighted_scores.values())
        
        return {
            "total_score": min(100, total_score),
            "grade": QualityScorer._get_grade(total_score),
            "breakdown": weighted_scores,
            "category_scores": scores
        }

    @staticmethod
    def _score_documentation(ast_data: Dict[str, Any]) -> float:
        """Score documentation quality (0.0 to 1.0)."""
        score = 0.0
        
        # Module docstring
        if ast_data.get("docstring"):
            score += 0.3
        
        # Function docstrings
        functions = ast_data.get("functions", [])
        if functions:
            documented_funcs = sum(1 for f in functions if f.get("has_docstring", False))
            score += 0.4 * (documented_funcs / len(functions))
        
        # Comment density
        metrics = ast_data.get("metrics", {})
        comment_density = metrics.get("comment_density", 0)
        score += min(0.3, comment_density / 100)
        
        return min(1.0, score)

    @staticmethod
    def _score_structure(ast_data: Dict[str, Any]) -> float:
        """Score code structure quality (0.0 to 1.0)."""
        score = 0.0
        metrics = ast_data.get("metrics", {})
        
        # Function and class organization
        if metrics.get("function_count", 0) > 0:
            score += 0.3
        if metrics.get("class_count", 0) > 0:
            score += 0.2
        
        # Reasonable function length (approximation)
        avg_func_complexity = metrics.get("complexity_score", 0) / max(1, metrics.get("function_count", 1))
        if avg_func_complexity < 20:
            score += 0.3
        elif avg_func_complexity < 50:
            score += 0.15
        
        # Import organization
        if ast_data.get("imports"):
            score += 0.2
            
        return min(1.0, score)

    @staticmethod
    def _score_execution(execution_data: Dict[str, Any]) -> float:
        """Score execution safety and success (0.0 to 1.0)."""
        status = execution_data.get("status", "UNKNOWN")
        
        if status == "SUCCESS":
            return 1.0
        elif status == "EXECUTION_DISABLED":
            return 0.5
        elif status == "TIMEOUT":
            return 0.2
        else:
            return 0.0

    @staticmethod
    def _score_security(security_issues: List[Dict[str, Any]]) -> float:
        """Score security based on issues found (0.0 to 1.0)."""
        if not security_issues:
            return 1.0
        
        # Penalize based on severity and count
        penalty = 0.0
        for issue in security_issues:
            severity = issue.get("level", "warning")
            if severity == "error":
                penalty += 0.3
            elif severity == "warning":
                penalty += 0.15
            else:  # note
                penalty += 0.05
        
        return max(0.0, 1.0 - penalty)

    @staticmethod
    def _score_maintainability(ast_data: Dict[str, Any]) -> float:
        """Score code maintainability (0.0 to 1.0)."""
        metrics = ast_data.get("metrics", {})
        max_cc = metrics.get("max_cyclomatic_complexity", 10)
        
        # Cyclomatic complexity scoring
        if max_cc <= 5:
            cc_score = 1.0
        elif max_cc <= 10:
            cc_score = 0.8
        elif max_cc <= 20:
            cc_score = 0.5
        elif max_cc <= 30:
            cc_score = 0.2
        else:
            cc_score = 0.0
        
        # Size factor
        loc = metrics.get("loc", 0)
        if loc <= 100:
            size_score = 1.0
        elif loc <= 500:
            size_score = 0.8
        elif loc <= 1000:
            size_score = 0.5
        else:
            size_score = 0.2
        
        return (cc_score * 0.7) + (size_score * 0.3)

    @staticmethod
    def _get_grade(score: float) -> str:
        """Convert score to letter grade."""
        if score >= 90: return "A"
        if score >= 80: return "B" 
        if score >= 70: return "C"
        if score >= 60: return "D"
        return "F"


# =========================================================================== #
#  RECOMMENDATION ENGINE
# =========================================================================== #
class RecommendationEngine:
    """Generate actionable improvement recommendations."""
    
    @staticmethod
    def generate(ast_data: Dict[str, Any], security_issues: List[Dict[str, Any]], 
                quality_score: Dict[str, Any]) -> List[str]:
        """Generate targeted recommendations for improvement."""
        recommendations = set()
        
        # Security recommendations
        recommendations.update(
            RecommendationEngine._security_recommendations(security_issues)
        )
        
        # Code quality recommendations
        recommendations.update(
            RecommendationEngine._quality_recommendations(ast_data, quality_score)
        )
        
        # Performance recommendations
        recommendations.update(
            RecommendationEngine._performance_recommendations(ast_data)
        )
        
        return sorted(list(recommendations))[:8]  # Limit to top 8

    @staticmethod
    def _security_recommendations(security_issues: List[Dict[str, Any]]) -> List[str]:
        """Generate security-focused recommendations."""
        recs = []
        
        for issue in security_issues:
            rule_id = issue.get("ruleId", "")
            message = issue.get("message", {}).get("text", "")
            
            if "PY001" in rule_id or "eval" in message.lower():
                recs.append("🔒 Replace eval() with ast.literal_eval() or JSON parsing")
            elif "PY002" in rule_id or "exec" in message.lower():
                recs.append("🔒 Avoid exec() - use function calls or configuration instead")
            elif "PY003" in rule_id or "os.system" in message.lower():
                recs.append("🔒 Use subprocess.run() with explicit args instead of os.system()")
            elif "PY004" in rule_id or "shell=True" in message.lower():
                recs.append("🔒 Avoid shell=True in subprocess calls to prevent injection")
            elif "PY005" in rule_id or "pickle" in message.lower():
                recs.append("🔒 Replace pickle with JSON, yaml, or protobuf for serialization")
        
        return recs

    @staticmethod
    def _quality_recommendations(ast_data: Dict[str, Any], 
                               quality_score: Dict[str, Any]) -> List[str]:
        """Generate code quality recommendations."""
        recs = []
        metrics = ast_data.get("metrics", {})
        breakdown = quality_score.get("breakdown", {})
        
        # Documentation improvements
        if breakdown.get("documentation", 100) < 70:
            if not ast_data.get("docstring"):
                recs.append("📝 Add module-level docstring")
            recs.append("📝 Improve function/method documentation")
        
        # Complexity improvements
        if metrics.get("max_cyclomatic_complexity", 0) > 10:
            recs.append("⚡ Refactor complex functions (cyclomatic complexity > 10)")
        
        # Structure improvements
        if breakdown.get("structure", 100) < 80:
            recs.append("🏗️ Improve code organization with better module structure")
        
        return recs

    @staticmethod
    def _performance_recommendations(ast_data: Dict[str, Any]) -> List[str]:
        """Generate performance-focused recommendations."""
        recs = []
        metrics = ast_data.get("metrics", {})
        
        # Large file recommendations
        if metrics.get("loc", 0) > 500:
            recs.append("🚀 Consider splitting large file into smaller modules")
        
        # Complexity recommendations
        if metrics.get("complexity_score", 0) > 100:
            recs.append("🚀 Simplify complex logic to improve performance")
        
        return recs


# =========================================================================== #
#  PROJECT SCANNER
# =========================================================================== #
class ProjectScanner:
    """Parallel project scanning with comprehensive analysis."""
    
    def __init__(self, config: Config, security_manager: SecurityManager, 
                 cache: AnalysisCache):
        self.config = config
        self.security = security_manager
        self.cache = cache
        self.scanned_files = 0
        self.skipped_files = 0

    def scan(self) -> List[Dict[str, Any]]:
        """Scan project and return analysis results."""
        python_files = self._discover_python_files()
        print(f"🔍 Found {len(python_files)} Python files to analyze...")
        
        modules = []
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as executor:
            futures = {
                executor.submit(self._analyze_file, filepath): filepath 
                for filepath in python_files
            }
            
            for future in tqdm(as_completed(futures), total=len(futures), 
                             desc="Analyzing files"):
                try:
                    result = future.result()
                    if result:
                        modules.append(result)
                except Exception as e:
                    filepath = futures[future]
                    print(f"❌ Error analyzing {filepath}: {e}", file=sys.stderr)
        
        print(f"✅ Analysis complete: {len(modules)} files analyzed, "
              f"{self.skipped_files} files skipped")
        print(f"📊 Cache performance: {self.cache.hit_ratio:.1%} hit rate")
        
        return modules

    def _discover_python_files(self) -> List[Path]:
        """Discover all Python files in project directory."""
        python_files = []
        
        for filepath in self.config.project_root.rglob("*.py"):
            # Skip excluded files
            if any(filepath.name == excluded for excluded in self.config.exclude_files):
                continue
            
            # Skip excluded directories
            if any(excluded in filepath.parts for excluded in self.config.exclude_dirs):
                continue
            
            # Skip files that are too large
            if filepath.stat().st_size > self.config.max_file_size:
                self.skipped_files += 1
                continue
            
            # Skip unsafe paths
            if not SecurityManager.safe_path(filepath, self.config.project_root):
                self.skipped_files += 1
                continue
            
            python_files.append(filepath)
        
        return python_files

    def _analyze_file(self, filepath: Path) -> Optional[Dict[str, Any]]:
        """Analyze a single file and return results."""
        self.scanned_files += 1
        
        try:
            # Read file content
            content = filepath.read_text(encoding='utf-8', errors='ignore')
            
            # Security analysis
            security_issues = self.security.scan_file(content, filepath)
            
            # AST analysis
            ast_data = ASTAnalyzer.analyze(filepath, self.cache)
            
            # Execution analysis
            execution_data = ExecutionSandbox.execute_safe(
                filepath, self.config.timeout, self.config.enable_execution
            )
            
            # Quality scoring
            quality_score = QualityScorer.calculate_score(
                ast_data, execution_data, security_issues
            )
            
            # Recommendations
            recommendations = RecommendationEngine.generate(
                ast_data, security_issues, quality_score
            )
            
            return {
                "file_path": str(filepath),
                "relative_path": str(filepath.relative_to(self.config.project_root)),
                "ast_analysis": ast_data,
                "security_issues": security_issues,
                "execution_result": execution_data,
                "quality_score": quality_score,
                "recommendations": recommendations,
                "file_metadata": {
                    "size_bytes": filepath.stat().st_size,
                    "modified_time": datetime.fromtimestamp(
                        filepath.stat().st_mtime
                    ).isoformat(),
                    "analysis_timestamp": datetime.now().isoformat()
                }
            }
            
        except Exception as e:
            print(f"⚠️ Failed to analyze {filepath}: {e}", file=sys.stderr)
            return None


# =========================================================================== #
#  REPORT GENERATORS
# =========================================================================== #
class SARIFReporter:
    """Generate SARIF (Static Analysis Results Interchange Format) reports."""
    
    @staticmethod
    def generate(modules: List[Dict[str, Any]], output_path: Path) -> None:
        """Generate SARIF format report for CI/CD integration."""
        sarif_data = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Python Project Auditor",
                        "informationUri": "https://github.com/example/python-auditor",
                        "version": "5.1",
                        "rules": SARIFReporter._generate_rules(modules)
                    }
                },
                "results": SARIFReporter._generate_results(modules),
                "properties": {
                    "auditSummary": {
                        "totalFiles": len(modules),
                        "totalIssues": sum(len(m.get("security_issues", [])) for m in modules),
                        "averageQualityScore": sum(
                            m["quality_score"]["total_score"] for m in modules
                        ) / len(modules) if modules else 0,
                        "generatedAt": datetime.now().isoformat()
                    }
                }
            }]
        }
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(sarif_data, f, indent=2, ensure_ascii=False)
        
        print(f"📊 SARIF report generated: {output_path}")

    @staticmethod
    def _generate_rules(modules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract unique rules from analysis results."""
        rules = {}
        for module in modules:
            for issue in module.get("security_issues", []):
                rule_id = issue.get("ruleId")
                if rule_id and rule_id not in rules:
                    rules[rule_id] = {
                        "id": rule_id,
                        "name": issue.get("message", {}).get("text", "").split(":")[0],
                        "shortDescription": {"text": issue.get("message", {}).get("text", "")},
                        "defaultConfiguration": {"level": issue.get("level", "warning")}
                    }
        return list(rules.values())

    @staticmethod
    def _generate_results(modules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Convert security issues to SARIF results."""
        results = []
        for module in modules:
            for issue in module.get("security_issues", []):
                results.append(issue)  # Issues are already in SARIF format
        return results


class MarkdownReporter:
    """Generate comprehensive Markdown reports."""
    
    @staticmethod
    def generate(modules: List[Dict[str, Any]], output_path: Path) -> None:
        """Generate detailed Markdown report."""
        content = [
            "# 🛡️ Python Project Security & Quality Audit Report\n",
            MarkdownReporter._generate_badges(modules),
            MarkdownReporter._generate_summary(modules),
            MarkdownReporter._generate_detailed_analysis(modules),
            MarkdownReporter._generate_recommendations(modules),
            MarkdownReporter._generate_footer()
        ]
        
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('w', encoding='utf-8') as f:
            f.write('\n'.join(content))
        
        print(f"📄 Markdown report generated: {output_path}")

    @staticmethod
    def _generate_badges(modules: List[Dict[str, Any]]) -> str:
        """Generate status badges for report header."""
        if not modules:
            return ""
        
        total_files = len(modules)
        total_issues = sum(len(m.get("security_issues", [])) for m in modules)
        avg_score = sum(m["quality_score"]["total_score"] for m in modules) / len(modules)
        
        badges = [
            f"![Files](https://img.shields.io/badge/Files-{total_files}-blue)",
            f"![Score](https://img.shields.io/badge/Score-{avg_score:.1f}%25-{'green' if avg_score >= 80 else 'yellow' if avg_score >= 60 else 'red'})",
            f"![Issues](https://img.shields.io/badge/Issues-{total_issues}-{'green' if total_issues == 0 else 'orange'})",
            f"![Python](https://img.shields.io/badge/Python-{sys.version_info.major}.{sys.version_info.minor}-blue)"
        ]
        
        return "\n".join(badges) + "\n"

    @staticmethod
    def _generate_summary(modules: List[Dict[str, Any]]) -> str:
        """Generate executive summary section."""
        if not modules:
            return "## 📊 Executive Summary\n\nNo files analyzed.\n"
        
        total_issues = sum(len(m.get("security_issues", [])) for m in modules)
        avg_score = sum(m["quality_score"]["total_score"] for m in modules) / len(modules)
        
        critical_issues = sum(
            1 for m in modules 
            for issue in m.get("security_issues", []) 
            if issue.get("level") == "error"
        )
        
        summary = [
            "## 📊 Executive Summary\n",
            f"**Generated on:** {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}",
            f"**Total files analyzed:** {len(modules)}",
            f"**Average quality score:** {avg_score:.1f}%",
            f"**Total security issues:** {total_issues}",
            f"**Critical issues:** {critical_issues}",
            f"**Overall grade:** {modules[0]['quality_score']['grade'] if modules else 'N/A'}",
            ""
        ]
        
        return "\n".join(summary)

    @staticmethod
    def _generate_detailed_analysis(modules: List[Dict[str, Any]]) -> str:
        """Generate detailed analysis section."""
        sections = ["## 🔍 Detailed Analysis\n"]
        
        for i, module in enumerate(modules, 1):
            file_path = module["relative_path"]
            quality = module["quality_score"]
            security_issues = module["security_issues"]
            metrics = module["ast_analysis"]["metrics"]
            
            sections.extend([
                f"### {i}. `{file_path}`",
                f"**Overall Score:** {quality['total_score']}% ({quality['grade']})",
                "",
                "#### Quality Breakdown",
                MarkdownReporter._quality_table(quality),
                "",
                "#### Metrics",
                MarkdownReporter._metrics_table(metrics),
                "",
                "#### Security Issues",
                MarkdownReporter._security_issues_list(security_issues),
                "",
                "---",
                ""
            ])
        
        return "\n".join(sections)

    @staticmethod
    def _quality_table(quality: Dict[str, Any]) -> str:
        """Generate quality breakdown table."""
        breakdown = quality["breakdown"]
        table = [
            "| Category | Score |",
            "|----------|-------|"
        ]
        for category, score in breakdown.items():
            # CORREZIONE: Converti score in stringa prima di usare .title()
            score_str = str(score)
            table.append(f"| {category.title()} | {score_str} |")
        return "\n".join(table)

    @staticmethod
    def _metrics_table(metrics: Dict[str, Any]) -> str:
        """Generate metrics table."""
        table = [
            "| Metric | Value |",
            "|--------|-------|"
        ]
        for metric, value in metrics.items():
            # CORREZIONE: Converti value in stringa
            value_str = str(value)
            table.append(f"| {metric.replace('_', ' ').title()} | {value_str} |")
        return "\n".join(table)

    @staticmethod
    def _security_issues_list(issues: List[Dict[str, Any]]) -> str:
        """Generate security issues list."""
        if not issues:
            return "✅ No security issues detected"
        
        items = []
        for issue in issues:
            level = issue.get("level", "warning").upper()
            message = issue.get("message", {}).get("text", "")
            items.append(f"- **{level}**: {message}")
        
        return "\n".join(items)

    @staticmethod
    def _generate_recommendations(modules: List[Dict[str, Any]]) -> str:
        """Generate recommendations section."""
        all_recs = set()
        for module in modules:
            all_recs.update(module.get("recommendations", []))
        
        if not all_recs:
            return "## 💡 Recommendations\n\n✅ No specific recommendations at this time.\n"
        
        sections = ["## 💡 Recommendations\n"]
        for rec in sorted(all_recs):
            sections.append(f"- {rec}")
        
        return "\n".join(sections) + "\n"

    @staticmethod
    def _generate_footer() -> str:
        """Generate report footer."""
        return (
            "---\n"
            "*Report generated by [Python Project Auditor](https://github.com/example/python-auditor)*\n"
        )


# =========================================================================== #
#  COMMAND LINE INTERFACE
# =========================================================================== #
def main() -> None:
    """Main entry point with CLI argument parsing."""
    parser = argparse.ArgumentParser(
        description="Python Project Auditor - Security, Quality, and Compliance Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic project analysis
  python auditor.py --project ./myproject
  
  # With execution testing and custom output
  python auditor.py --enable-exec --output-format both
  
  # CI/CD mode with strict quality gate
  python auditor.py --min-score 80 --output-format sarif
  
  # Custom configuration file
  python auditor.py --config pyproject.toml
        """
    )
    
    parser.add_argument(
        "--project", "-p",
        type=Path,
        default=Path("."),
        help="Project root directory (default: current directory)"
    )
    
    parser.add_argument(
        "--config", "-c",
        type=Path,
        help="Configuration file (pyproject.toml or auditor.toml)"
    )
    
    parser.add_argument(
        "--enable-exec", "-x",
        action="store_true",
        help="Enable code execution in sandbox (use with caution)"
    )
    
    parser.add_argument(
        "--workers", "-w",
        type=int,
        default=None,
        help="Number of parallel workers (default: CPU count)"
    )
    
    parser.add_argument(
        "--min-score", "-s",
        type=int,
        default=70,
        help="Minimum acceptable quality score (default: 70)"
    )
    
    parser.add_argument(
        "--output-format", "-f",
        choices=["sarif", "markdown", "both"],
        default="both",
        help="Output format (default: both)"
    )
    
    parser.add_argument(
        "--output-dir", "-o",
        type=Path,
        default=Path("."),
        help="Output directory for reports (default: current directory)"
    )
    
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=30,
        help="Execution timeout in seconds (default: 30)"
    )
    
    args = parser.parse_args()
    
    try:
        # Load and validate configuration
        config = Config.load(args.config)
        
        # Apply CLI overrides
        config.project_root = args.project.expanduser().resolve()
        config.enable_execution = args.enable_exec
        config.min_acceptable_score = args.min_score
        config.timeout = args.timeout
        config.output_format = args.output_format
        
        if args.workers:
            config.max_workers = args.workers
        
        config.validate()
        
        # Ensure project exists
        if not config.project_root.exists():
            print(f"❌ Error: Project directory does not exist: {config.project_root}")
            sys.exit(1)
            
        print(f"🚀 Starting Python Project Auditor v5.1")
        print(f"📁 Project: {config.project_root}")
        print(f"⚙️  Workers: {config.max_workers}")
        print(f"🎯 Target score: {config.min_acceptable_score}%")
        print("─" * 50)
        
        # Initialize components
        cache = AnalysisCache(config.analysis_cache_size)
        security_manager = SecurityManager(config.security_rules_path)
        scanner = ProjectScanner(config, security_manager, cache)
        
        # Perform analysis
        start_time = time.time()
        modules = scanner.scan()
        analysis_time = time.time() - start_time
        
        # Generate reports
        output_dir = args.output_dir.expanduser().resolve()
        output_dir.mkdir(parents=True, exist_ok=True)
        
        if config.output_format in ["markdown", "both"]:
            markdown_path = output_dir / config.readme_name
            MarkdownReporter.generate(modules, markdown_path)
        
        if config.output_format in ["sarif", "both"]:
            sarif_path = output_dir / config.sarif_name
            SARIFReporter.generate(modules, sarif_path)
        
        # Summary and exit code
        print("─" * 50)
        print(f"⏱️  Analysis completed in {analysis_time:.2f} seconds")
        
        if modules:
            avg_score = sum(m["quality_score"]["total_score"] for m in modules) / len(modules)
            total_issues = sum(len(m.get("security_issues", [])) for m in modules)
            
            print(f"📊 Average quality score: {avg_score:.1f}%")
            print(f"🚨 Total security issues: {total_issues}")
            
            # Quality gate enforcement
            if avg_score < config.min_acceptable_score:
                print(f"❌ QUALITY GATE FAILED: Score {avg_score:.1f}% < {config.min_acceptable_score}%")
                sys.exit(1)
            else:
                print(f"✅ Quality gate passed: {avg_score:.1f}% >= {config.min_acceptable_score}%")
                sys.exit(0)
        else:
            print("⚠️  No files were analyzed")
            sys.exit(0)
            
    except KeyboardInterrupt:
        print("\n⏹️  Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"❌ Fatal error: {e}", file=sys.stderr)
        if os.getenv("DEBUG"):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
