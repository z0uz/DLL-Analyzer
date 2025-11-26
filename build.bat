@echo off
REM Batch file for DLL Analyzer development commands
REM Windows-compatible alternative to Makefile

if "%1"=="" goto help
if "%1"=="help" goto help
if "%1"=="install" goto install
if "%1"=="install-dev" goto install_dev
if "%1"=="test" goto test
if "%1"=="lint" goto lint
if "%1"=="format" goto format
if "%1"=="clean" goto clean
if "%1"=="run" goto run
if "%1"=="web" goto web
if "%1"=="docs" goto docs
if "%1"=="package" goto package
if "%1"=="check" goto check
if "%1"=="dev-setup" goto dev_setup
if "%1"=="analyze-example" goto analyze_example
if "%1"=="init-db" goto init_db
if "%1"=="create-plugin" goto create_plugin
if "%1"=="security-audit" goto security_audit
if "%1"=="benchmark" goto benchmark

:help
echo DLL Analyzer - Windows Development Commands
echo.
echo Available commands:
echo   install      Install the package
echo   install-dev  Install with development dependencies
echo   test         Run all tests
echo   lint         Run code linting
echo   format       Format code with black
echo   clean        Clean temporary files
echo   run          Run the main analyzer
echo   web          Start web interface
echo   docs         Generate documentation
echo   package      Create distribution package
echo   check        Run lint and tests
echo   dev-setup    Complete development environment setup
echo   analyze-example Analyze system DLL example
echo   init-db      Initialize database
echo   create-plugin Create plugin template
echo   security-audit Run security audit
echo   benchmark    Performance testing
echo.
echo Usage:
echo   build.bat install-dev
echo   build.bat test
echo   build.bat run
goto end

:install
echo Installing DLL Analyzer package...
pip install -e .
if %ERRORLEVEL% equ 0 (
    echo ✓ Package installed successfully
) else (
    echo ✗ Package installation failed
)
goto end

:install_dev
echo Installing with development dependencies...
pip install -e ".[dev,web,docs]"
if %ERRORLEVEL% equ 0 (
    echo ✓ Development environment ready!
    echo Consider installing pre-commit hooks manually if needed
) else (
    echo ✗ Development installation failed
)
goto end

:test
echo Running tests...
python tests.py -v
if %ERRORLEVEL% equ 0 (
    echo ✓ All tests passed
) else (
    echo ✗ Some tests failed
)
goto end

:lint
echo Running code linting...
flake8 *.py
if %ERRORLEVEL% equ 0 (
    echo ✓ Code linting passed
) else (
    echo ✗ Linting issues found
)

echo Running type checking...
mypy *.py --ignore-missing-imports
if %ERRORLEVEL% equ 0 (
    echo ✓ Type checking passed
) else (
    echo ✗ Type checking issues found
)
goto end

:format
echo Formatting code...
black *.py
if %ERRORLEVEL% equ 0 (
    echo ✓ Code formatted with black
)

isort *.py
if %ERRORLEVEL% equ 0 (
    echo ✓ Imports sorted with isort
)
goto end

:clean
echo Cleaning temporary files...

REM Remove Python cache files (if possible)
for /r %%i in (*.pyc) do del "%%i" 2>nul
for /d /r %%i in (__pycache__) do rmdir /s /q "%%i" 2>nul

REM Remove build artifacts
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
for /d %%i in (*.egg-info) do rmdir /s /q "%%i" 2>nul

REM Remove test and coverage artifacts
if exist htmlcov rmdir /s /q htmlcov
if exist .coverage del .coverage 2>nul
if exist .pytest_cache rmdir /s /q .pytest_cache 2>nul

REM Remove database and log files
del *.db 2>nul
del *.log 2>nul

echo ✓ Project cleaned
goto end

:run
echo Running DLL Analyzer...
python dll_analyzer.py
goto end

:web
echo Starting web interface...
echo Web interface will be available at http://localhost:5000
python web_interface.py
goto end

:docs
echo Generating documentation...
if exist docs (
    sphinx-build -b html docs/ docs/_build/html
    if %ERRORLEVEL% equ 0 (
        echo ✓ Documentation generated at docs\_build\html\index.html
    ) else (
        echo ✗ Documentation generation failed
    )
) else (
    echo docs directory not found
)
goto end

:package
echo Creating distribution package...
python setup.py sdist bdist_wheel
if %ERRORLEVEL% equ 0 (
    echo ✓ Package created in dist\ directory
) else (
    echo ✗ Package creation failed
)
goto end

:check
echo Running all checks...
call :lint
call :test
if %ERRORLEVEL% equ 0 (
    echo ✓ All checks passed!
) else (
    echo ✗ Some checks failed
)
goto end

:dev_setup
echo Setting up complete development environment...
call :install_dev
echo ✓ Development environment ready!
goto end

:analyze_example
echo Running example analysis...
set dllPath=C:\Windows\System32\kernel32.dll
if exist "%dllPath%" (
    python dll_analyzer.py "%dllPath%"
) else (
    echo System DLL not found at %dllPath%
    echo Please provide a valid DLL path
)
goto end

:init_db
echo Initializing database...
python -c "from database import AnalysisDatabase; AnalysisDatabase()"
if %ERRORLEVEL% equ 0 (
    echo ✓ Database initialized
) else (
    echo ✗ Database initialization failed
)
goto end

:create_plugin
echo Creating plugin template...

REM Create plugins directory if it doesn't exist
if not exist plugins mkdir plugins

REM Create plugin template file
echo from plugin_system import AnalysisPlugin > plugins\custom_plugin.py
echo. >> plugins\custom_plugin.py
echo class CustomPlugin(AnalysisPlugin): >> plugins\custom_plugin.py
echo     @property >> plugins\custom_plugin.py
echo     def name(self): >> plugins\custom_plugin.py
echo         return "custom_plugin" >> plugins\custom_plugin.py
echo. >> plugins\custom_plugin.py
echo     @property >> plugins\custom_plugin.py
echo     def version(self): >> plugins\custom_plugin.py
echo         return "1.0.0" >> plugins\custom_plugin.py
echo. >> plugins\custom_plugin.py
echo     @property >> plugins\custom_plugin.py
echo     def description(self): >> plugins\custom_plugin.py
echo         return "Custom analysis plugin" >> plugins\custom_plugin.py
echo. >> plugins\custom_plugin.py
echo     def analyze(self, pe_file, config): >> plugins\custom_plugin.py
echo         return {"result": "custom_analysis"} >> plugins\custom_plugin.py

echo ✓ Plugin template created at plugins\custom_plugin.py
goto end

:security_audit
echo Running security audit...
bandit -r . -f json -o security-report.json
if %ERRORLEVEL% equ 0 (
    echo ✓ Security audit completed
)

safety check
if %ERRORLEVEL% equ 0 (
    echo ✓ Dependency security check passed
)
goto end

:benchmark
echo Running performance benchmark...
python -m timeit -s "from dll_analyzer import DLLAnalyzer" "DLLAnalyzer('test_file')"
goto end

:end
echo Done.
