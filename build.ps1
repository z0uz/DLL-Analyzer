# PowerShell build script for DLL Analyzer
# Professional development automation for Windows

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("install", "install-dev", "test", "lint", "format", "clean", "run", "web", "docs", "package", "check", "dev-setup", "analyze-example", "init-db", "create-plugin", "security-audit", "benchmark")]
    [string]$Task = "help"
)

function Show-Help {
    Write-Host "DLL Analyzer - PowerShell Development Commands" -ForegroundColor Green
    Write-Host ""
    Write-Host "Available tasks:" -ForegroundColor Yellow
    Write-Host "  install      Install the package"
    Write-Host "  install-dev  Install with development dependencies"
    Write-Host "  test         Run all tests"
    Write-Host "  lint         Run code linting"
    Write-Host "  format       Format code with black"
    Write-Host "  clean        Clean temporary files"
    Write-Host "  run          Run the main analyzer"
    Write-Host "  web          Start web interface"
    Write-Host "  docs         Generate documentation"
    Write-Host "  package      Create distribution package"
    Write-Host "  check        Run lint and tests"
    Write-Host "  dev-setup    Complete development environment setup"
    Write-Host "  analyze-example Analyze system DLL example"
    Write-Host "  init-db      Initialize database"
    Write-Host "  create-plugin Create plugin template"
    Write-Host "  security-audit Run security audit"
    Write-Host "  benchmark    Performance testing"
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\build.ps1 install-dev"
    Write-Host "  .\build.ps1 test"
    Write-Host "  .\build.ps1 run"
}

function Install-Package {
    Write-Host "Installing DLL Analyzer package..." -ForegroundColor Blue
    pip install -e .
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Package installed successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Package installation failed" -ForegroundColor Red
    }
}

function Install-DevDependencies {
    Write-Host "Installing with development dependencies..." -ForegroundColor Blue
    pip install -e ".[dev,web,docs]"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Development environment ready!" -ForegroundColor Green
        Write-Host "Consider installing pre-commit hooks manually if needed" -ForegroundColor Yellow
    } else {
        Write-Host "✗ Development installation failed" -ForegroundColor Red
    }
}

function Run-Tests {
    Write-Host "Running tests..." -ForegroundColor Blue
    python tests.py -v
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ All tests passed" -ForegroundColor Green
    } else {
        Write-Host "✗ Some tests failed" -ForegroundColor Red
    }
}

function Run-Lint {
    Write-Host "Running code linting..." -ForegroundColor Blue
    flake8 *.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Code linting passed" -ForegroundColor Green
    } else {
        Write-Host "✗ Linting issues found" -ForegroundColor Red
    }
    
    Write-Host "Running type checking..." -ForegroundColor Blue
    mypy *.py --ignore-missing-imports
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Type checking passed" -ForegroundColor Green
    } else {
        Write-Host "✗ Type checking issues found" -ForegroundColor Yellow
    }
}

function Format-Code {
    Write-Host "Formatting code..." -ForegroundColor Blue
    black *.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Code formatted with black" -ForegroundColor Green
    }
    
    isort *.py
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Imports sorted with isort" -ForegroundColor Green
    }
}

function Clean-Project {
    Write-Host "Cleaning temporary files..." -ForegroundColor Blue
    
    # Remove Python cache files
    Get-ChildItem -Path . -Recurse -Name "*.pyc" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Path . -Recurse -Name "__pycache__" -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
    
    # Remove build artifacts
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path "*.egg-info") { Remove-Item -Recurse -Force "*.egg-info" }
    
    # Remove test and coverage artifacts
    if (Test-Path "htmlcov") { Remove-Item -Recurse -Force "htmlcov" }
    if (Test-Path ".coverage") { Remove-Item -Force ".coverage" }
    if (Test-Path ".pytest_cache") { Remove-Item -Recurse -Force ".pytest_cache" }
    
    # Remove database and log files
    Get-ChildItem -Name "*.db" -ErrorAction SilentlyContinue | Remove-Item -Force
    Get-ChildItem -Name "*.log" -ErrorAction SilentlyContinue | Remove-Item -Force
    
    Write-Host "✓ Project cleaned" -ForegroundColor Green
}

function Run-Analyzer {
    Write-Host "Running DLL Analyzer..." -ForegroundColor Blue
    python dll_analyzer.py
}

function Start-WebInterface {
    Write-Host "Starting web interface..." -ForegroundColor Blue
    Write-Host "Web interface will be available at http://localhost:5000" -ForegroundColor Yellow
    python web_interface.py
}

function Build-Docs {
    Write-Host "Generating documentation..." -ForegroundColor Blue
    if (Test-Path "docs") {
        sphinx-build -b html docs/ docs/_build/html
        if ($LASTEXITCODE -eq 0) {
            Write-Host "✓ Documentation generated at docs/_build/html/index.html" -ForegroundColor Green
        } else {
            Write-Host "✗ Documentation generation failed" -ForegroundColor Red
        }
    } else {
        Write-Host "docs directory not found" -ForegroundColor Yellow
    }
}

function Create-Package {
    Write-Host "Creating distribution package..." -ForegroundColor Blue
    python setup.py sdist bdist_wheel
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Package created in dist/ directory" -ForegroundColor Green
    } else {
        Write-Host "✗ Package creation failed" -ForegroundColor Red
    }
}

function Run-Checks {
    Write-Host "Running all checks..." -ForegroundColor Blue
    Run-Lint
    Run-Tests
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ All checks passed!" -ForegroundColor Green
    } else {
        Write-Host "✗ Some checks failed" -ForegroundColor Red
    }
}

function Setup-DevEnvironment {
    Write-Host "Setting up complete development environment..." -ForegroundColor Blue
    Install-DevDependencies
    Write-Host "✓ Development environment ready!" -ForegroundColor Green
}

function Analyze-Example {
    Write-Host "Running example analysis..." -ForegroundColor Blue
    $dllPath = "C:\Windows\System32\kernel32.dll"
    if (Test-Path $dllPath) {
        python dll_analyzer.py $dllPath
    } else {
        Write-Host "System DLL not found at $dllPath" -ForegroundColor Yellow
        Write-Host "Please provide a valid DLL path" -ForegroundColor Yellow
    }
}

function Initialize-Database {
    Write-Host "Initializing database..." -ForegroundColor Blue
    python -c "from database import AnalysisDatabase; AnalysisDatabase()"
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Database initialized" -ForegroundColor Green
    } else {
        Write-Host "✗ Database initialization failed" -ForegroundColor Red
    }
}

function Create-Plugin {
    Write-Host "Creating plugin template..." -ForegroundColor Blue
    
    # Create plugins directory if it doesn't exist
    if (!(Test-Path "plugins")) {
        New-Item -ItemType Directory -Name "plugins"
    }
    
    $pluginTemplate = @"
from plugin_system import AnalysisPlugin

class CustomPlugin(AnalysisPlugin):
    @property
    def name(self):
        return "custom_plugin"
    
    @property
    def version(self):
        return "1.0.0"
    
    @property
    def description(self):
        return "Custom analysis plugin"
    
    def analyze(self, pe_file, config):
        return {"result": "custom_analysis"}
"@
    
    $pluginTemplate | Set-Content -Path "plugins\custom_plugin.py"
    Write-Host "✓ Plugin template created at plugins\custom_plugin.py" -ForegroundColor Green
}

function Run-SecurityAudit {
    Write-Host "Running security audit..." -ForegroundColor Blue
    bandit -r . -f json -o security-report.json
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Security audit completed" -ForegroundColor Green
    }
    
    safety check
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Dependency security check passed" -ForegroundColor Green
    }
}

function Run-Benchmark {
    Write-Host "Running performance benchmark..." -ForegroundColor Blue
    python -m timeit -s "from dll_analyzer import DLLAnalyzer" "DLLAnalyzer('test_file')"
}

# Main execution
switch ($Task) {
    "help" { Show-Help }
    "install" { Install-Package }
    "install-dev" { Install-DevDependencies }
    "test" { Run-Tests }
    "lint" { Run-Lint }
    "format" { Format-Code }
    "clean" { Clean-Project }
    "run" { Run-Analyzer }
    "web" { Start-WebInterface }
    "docs" { Build-Docs }
    "package" { Create-Package }
    "check" { Run-Checks }
    "dev-setup" { Setup-DevEnvironment }
    "analyze-example" { Analyze-Example }
    "init-db" { Initialize-Database }
    "create-plugin" { Create-Plugin }
    "security-audit" { Run-SecurityAudit }
    "benchmark" { Run-Benchmark }
    default { 
        Write-Host "Unknown task: $Task" -ForegroundColor Red
        Show-Help
    }
}
