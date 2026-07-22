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
