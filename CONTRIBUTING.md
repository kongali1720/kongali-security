# Contributing to KONGALI SECURITY

Thank you for your interest in contributing to **KONGALI SECURITY**.

KONGALI SECURITY is an open-source cybersecurity and security automation framework designed for authorized security testing, defensive security operations, threat intelligence, security research, education, and automation.

We welcome contributions from developers, security researchers, documentation writers, testers, and the wider open-source community.

---

## Code of Conduct

By participating in this project, you agree to follow the project's [Code of Conduct](CODE_OF_CONDUCT.md).

All contributors are expected to communicate respectfully and constructively.

---

## Ways to Contribute

There are many ways to contribute to KONGALI SECURITY:

- Report bugs
- Suggest new features
- Improve existing functionality
- Add security analysis capabilities
- Improve IOC analysis
- Improve threat intelligence integrations
- Improve documentation
- Add unit tests
- Add integration tests
- Improve performance
- Improve CLI usability
- Improve error handling
- Review Pull Requests
- Improve security and hardening
- Share feedback and use cases

Every contribution is valuable.

---

## Before You Start

Before making a contribution:

1. Check existing Issues.
2. Check existing Pull Requests.
3. Search the documentation.
4. Make sure the proposed change is not already being developed.
5. Open an Issue for major changes before starting implementation.

For large architectural changes, please discuss the proposal with the maintainers first.

---

## Development Environment

KONGALI SECURITY is primarily developed using Python.

Recommended environment:

- Python 3.10+
- Git
- pip
- virtual environment
- pytest

Additional development tools may be required depending on the component being modified.

---

## Clone the Repository

Clone the repository:

```bash
git clone https://github.com/kongali1720/kongali-security.git
```

```bash
cd kongali-security
```

## 📦 Development Setup

Follow the steps below to set up a local development environment for **Kongali Security**.

### 1. Enter the Project Directory

After cloning the repository, navigate to the project directory:

    cd kongali-security

---

### 2. Create a Virtual Environment

It is recommended to use a Python virtual environment to isolate project dependencies.

#### Linux / macOS

    python3 -m venv .venv
    source .venv/bin/activate

#### Windows

    python -m venv .venv
    .venv\Scripts\activate

Once activated, your terminal should indicate that the `.venv` environment is active.

---

### 3. Install Development Dependencies

Install the Kongali Security package together with its development dependencies:

    pip install -e ".[dev]"

This installs the project in editable mode, allowing changes to the source code to be tested immediately without reinstalling the package.

If the development extras are not available, install the development requirements file instead:

    pip install -r requirements-dev.txt

---

### 4. Running Tests

Kongali Security uses **pytest** for automated testing.

#### Run the Complete Test Suite

    pytest

#### Run Tests with Verbose Output

    pytest -v

#### Run a Specific Test File

To run only the IOC Analyzer tests:

    pytest tests/test_ioc.py

You can also run the specific test file with verbose output:

    pytest tests/test_ioc.py -v

---

### 5. Development Workflow

A typical development workflow looks like this:

    Clone Repository
           │
           ▼
    cd kongali-security
           │
           ▼
    Create Virtual Environment
           │
           ▼
    Activate .venv
           │
           ▼
    Install Development Dependencies
           │
           ▼
    Develop / Modify Code
           │
           ▼
    Run Tests
           │
           ▼
    Review Results
           │
           ▼
    Commit Changes

---

### 6. Quick Setup

For experienced developers, the complete setup can be performed with:

#### Linux / macOS

    git clone https://github.com/kongali1720/kongali-security.git
    cd kongali-security
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -e ".[dev]"
    pytest -v

#### Windows

    git clone https://github.com/kongali1720/kongali-security.git
    cd kongali-security
    python -m venv .venv
    .venv\Scripts\activate
    pip install -e ".[dev]"
    pytest -v

> **Note:** Make sure the virtual environment is activated before installing dependencies or running the test suite.

---

# 🤝 Contributing to KONGALI SECURITY

Thank you for your interest in contributing to **KONGALI SECURITY**.

KONGALI SECURITY is an open-source cybersecurity and security automation framework focused on defensive security, security analysis, threat intelligence, automation, and responsible security research.

We welcome contributions from developers, cybersecurity professionals, security researchers, system administrators, students, technical writers, and open-source contributors.

By contributing to this project, you agree to follow the project's contribution guidelines, Code of Conduct, and responsible security principles.

---

## 📋 Table of Contents

- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Pull Requests](#pull-requests)
- [Pull Request Checklist](#pull-request-checklist)
- [Security Contributions](#security-contributions)
- [Responsible Security Research](#responsible-security-research)
- [Documentation Contributions](#documentation-contributions)
- [Issue Reports](#issue-reports)
- [Feature Requests](#feature-requests)
- [Review Process](#review-process)
- [Breaking Changes](#breaking-changes)
- [Dependencies](#dependencies)
- [Code Quality](#code-quality)
- [Testing](#testing)
- [Security Disclosure](#security-disclosure)
- [License](#license)

---

# 🚀 How to Contribute

There are many ways to contribute to KONGALI SECURITY.

You can contribute through:

- Python development
- Security engineering
- Threat intelligence
- IOC analysis
- Detection engineering
- OSINT research
- Network security
- Security automation
- AI-assisted security research
- Testing
- Documentation
- DevOps
- CI/CD improvements
- Security hardening
- Bug reports
- Feature requests
- Architecture improvements
- Educational content

Before starting significant work, consider opening an Issue or discussing the proposed change with the maintainers.

This helps prevent duplicated work and ensures that larger changes align with the project's architecture and roadmap.

---

# 🛠️ Development Setup

## 1. Clone the Repository

    git clone https://github.com/kongali1720/kongali-security.git

Enter the project directory:

    cd kongali-security

---

## 2. Create a Virtual Environment

It is recommended to use a Python virtual environment to isolate project dependencies.

### Linux / macOS

    python3 -m venv .venv
    source .venv/bin/activate

### Windows

    python -m venv .venv
    .venv\Scripts\activate

---

## 3. Install Development Dependencies

Install the project and development dependencies:

    pip install -e ".[dev]"

If development extras are not available, install the development requirements:

    pip install -r requirements-dev.txt

---

## 4. Run Tests

Run the complete test suite:

    pytest

Run tests with verbose output:

    pytest -v

Run a specific test file:

    pytest tests/test_ioc.py

---

## 5. Run Code Quality Checks

Where applicable, run linting and static analysis before submitting changes.

Run Ruff:

    ruff check .

Format code:

    ruff format .

Run MyPy:

    mypy kongali_security

Run security analysis:

    bandit -r kongali_security

Audit Python dependencies:

    pip-audit

---

# 🔀 Pull Requests

Before opening a Pull Request:

- Update your branch with the latest `main`.
- Run the relevant tests.
- Run linting and security checks where applicable.
- Review your own changes.
- Remove debugging code.
- Make sure no secrets or credentials are included.
- Update documentation if necessary.
- Add tests for new functionality where appropriate.

Your Pull Request should clearly explain:

- What changed.
- Why the change was needed.
- How the change was implemented.
- How the change was tested.
- Any potential security impact.

Keep Pull Requests focused and limited to a clear, relevant scope whenever possible.

---

# ✅ Pull Request Checklist

Before submitting a Pull Request, verify:

- [ ] The code follows the project's style.
- [ ] Tests have been added or updated where appropriate.
- [ ] Existing tests pass.
- [ ] Documentation has been updated where necessary.
- [ ] No credentials or secrets are included.
- [ ] No sensitive information is included.
- [ ] Security implications have been considered.
- [ ] The Pull Request has a clear description.
- [ ] The changes are focused and relevant.
- [ ] Debugging code has been removed.
- [ ] Relevant linting checks have been completed.
- [ ] Relevant security checks have been completed.

---

# 🛡️ Security Contributions

Security-related contributions are highly encouraged.

Examples include:

- Input validation
- Secure error handling
- Authentication improvements
- Authorization improvements
- Dependency security
- Secure configuration
- Secret management
- Logging improvements
- Detection improvements
- Threat intelligence improvements
- Security hardening
- Secure defaults
- Security monitoring
- Defensive automation

Security contributions should prioritize maintainability, correctness, and responsible disclosure practices.

For previously unknown security vulnerabilities, please follow the instructions in:

    SECURITY.md

Do not publicly disclose an unpatched vulnerability through a GitHub Issue or Pull Request.

---

# 🔐 Responsible Security Research

KONGALI SECURITY is intended for legitimate and authorized security activities.

Contributors must not use the project to:

- Access systems without authorization.
- Attack third-party infrastructure.
- Disrupt services.
- Steal credentials.
- Exfiltrate data.
- Deploy malware.
- Conduct unauthorized surveillance.
- Perform illegal activities.

All security testing must be performed against systems that you own or have explicit authorization to test.

Contributors are responsible for complying with all applicable laws, regulations, contracts, and organizational policies.

The project maintainers do not endorse or authorize unauthorized security activity.

---

# 📚 Documentation Contributions

Documentation improvements are welcome.

You can contribute by:

- Fixing spelling or grammar.
- Improving technical explanations.
- Adding examples.
- Improving installation instructions.
- Adding troubleshooting information.
- Improving API documentation.
- Adding architecture diagrams.
- Improving developer documentation.
- Translating documentation.
- Improving security documentation.

Documentation changes should be:

- Clear.
- Accurate.
- Technically correct.
- Easy to understand.
- Consistent with the current project behavior.

When documenting security functionality, avoid publishing sensitive information, credentials, private infrastructure details, or undisclosed vulnerabilities.

---

# 🐛 Issue Reports

When reporting a bug, please include as much relevant information as possible.

Please include:

- Operating system.
- Python version.
- KONGALI SECURITY version.
- Installation method.
- Relevant configuration.
- Steps to reproduce.
- Expected behavior.
- Actual behavior.
- Error messages or logs.
- Relevant environment information.

Please remove the following before submitting an Issue:

- Passwords.
- API keys.
- Access tokens.
- Private keys.
- Credentials.
- Personal information.
- Internal infrastructure information.
- Other sensitive data.

A minimal reproducible example is highly appreciated when applicable.

---

# 💡 Feature Requests

Feature requests should explain:

- The problem being solved.
- The proposed solution.
- Why the feature is useful.
- Potential alternatives.
- Potential security implications.
- Potential impact on existing functionality.

Large features should be discussed with maintainers before implementation whenever possible.

Feature proposals should consider:

- Project architecture.
- Maintainability.
- Performance.
- Security.
- Backward compatibility.
- Testing requirements.
- Documentation requirements.

---

# 🔍 Review Process

Pull Requests may be reviewed for:

- Correctness.
- Maintainability.
- Code quality.
- Test coverage.
- Security impact.
- Performance.
- Documentation.
- Backward compatibility.
- Dependency impact.
- API stability.

Maintainers may request changes before a Pull Request is merged.

Contributors should respond to review feedback constructively and update their Pull Requests as necessary.

Approval does not guarantee immediate merging. Maintainers may consider the project's roadmap, release schedule, architectural direction, and security requirements.

---

# ⚠️ Breaking Changes

Changes that may break existing functionality should be clearly documented.

Examples include:

- Public API changes.
- CLI behavior changes.
- Configuration changes.
- Removed functionality.
- Changed default behavior.
- Changed output formats.
- Changed dependency requirements.
- Changes to module interfaces.

Breaking changes should be discussed with maintainers before implementation whenever possible.

When a breaking change is necessary, the Pull Request should clearly explain:

- What is changing.
- Why the change is necessary.
- Who may be affected.
- How users can migrate.
- Whether backward compatibility can be maintained.

---

# 📦 Dependencies

When adding a new dependency:

- Explain why it is necessary.
- Prefer well-maintained projects.
- Consider license compatibility.
- Consider security history.
- Consider project activity and maintenance.
- Avoid unnecessary dependencies.
- Keep dependencies up to date.
- Review known vulnerabilities.
- Consider dependency size and performance impact.

Do not introduce dependencies that are not required by the project.

New dependencies should be added to the appropriate dependency configuration and documented when necessary.

Security-sensitive dependencies should receive additional review before being introduced.

---

# 🧹 Code Quality

Contributions should follow the project's coding standards.

Python code should generally:

- Follow PEP 8 principles.
- Use clear and descriptive names.
- Include type hints where appropriate.
- Include docstrings for public APIs.
- Avoid unnecessary complexity.
- Handle errors safely.
- Avoid exposing sensitive information.
- Avoid hard-coded credentials.
- Prefer secure defaults.

Before submitting a Pull Request, contributors should review their own code for:

- Unused imports.
- Debugging statements.
- Dead code.
- Hard-coded secrets.
- Unnecessary dependencies.
- Poor error handling.
- Missing validation.
- Missing tests.
- Documentation gaps.

---

# 🧪 Testing

New functionality should include appropriate tests whenever practical.

Tests should cover:

- Normal behavior.
- Expected edge cases.
- Invalid input.
- Error handling.
- Security-sensitive behavior.
- Backward compatibility where applicable.

Run the complete test suite before submitting a Pull Request:

    pytest

Run tests with verbose output:

    pytest -v

Run a specific test:

    pytest tests/test_ioc.py -v

Contributors should ensure that existing tests continue to pass unless the Pull Request intentionally changes expected behavior.

---

# 🔒 Security Disclosure

Security vulnerabilities should not be publicly disclosed through:

- GitHub Issues.
- Pull Requests.
- Public discussions.
- Public comments.

For previously unknown or sensitive security vulnerabilities, please follow the responsible disclosure process described in:

    SECURITY.md

Please provide maintainers with sufficient information to reproduce and investigate the vulnerability.

Do not publicly disclose sensitive vulnerability details until the issue has been responsibly handled.

---

# 🌐 Security and Privacy Principles

Contributors should follow these principles when developing or modifying KONGALI SECURITY:

- Security by design.
- Secure by default.
- Least privilege.
- Defense in depth.
- Input validation.
- Safe error handling.
- Minimal data collection.
- No unnecessary credential exposure.
- Responsible logging.
- Privacy-aware development.
- Transparent security practices.

Security-related functionality should be designed with legitimate defensive use cases in mind.

---

# 🤝 Community Standards

All contributors are expected to communicate respectfully and professionally.

Contributors should:

- Be respectful.
- Provide constructive feedback.
- Focus on technical issues.
- Avoid harassment.
- Avoid discriminatory behavior.
- Respect different levels of experience.
- Help maintain a welcoming open-source community.

Please also review:

    CODE_OF_CONDUCT.md

---

# 📝 Commit Guidelines

Write clear and descriptive commit messages.

Good examples:

    Add IOC analyzer for IPv4 and IPv6 detection

    Improve DNS analysis error handling

    Add unit tests for hash detection

    Update security contribution guidelines

Avoid vague commit messages such as:

    update

    fix

    changes

    test

Keep commits focused whenever possible.

---

# 🌿 Branch Guidelines

For development work, create a dedicated branch instead of committing directly to `main`.

Example:

    git checkout -b feature/ioc-analyzer

Or:

    git checkout -b fix/dns-validation

After completing your work:

    git status

    git add .

    git commit -m "Add IOC analyzer improvements"

    git push origin feature/ioc-analyzer

Then open a Pull Request against the `main` branch.

---

# 🚀 Contribution Workflow

The recommended contribution workflow is:

    Fork Repository
          │
          ▼
    Clone Repository
          │
          ▼
    Create Feature Branch
          │
          ▼
    Make Changes
          │
          ▼
    Add or Update Tests
          │
          ▼
    Run Test Suite
          │
          ▼
    Run Linting
          │
          ▼
    Run Security Checks
          │
          ▼
    Review Your Changes
          │
          ▼
    Push Branch
          │
          ▼
    Open Pull Request
          │
          ▼
    Code Review
          │
          ▼
    Maintainer Approval
          │
          ▼
    Merge
```
