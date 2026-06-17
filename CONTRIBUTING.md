# Contributing to DomaScan

Thank you for your interest in contributing to **DomaScan**! Contributions are welcome and appreciated. This document provides guidelines and instructions for contributing to this project.

**Project Maintainer:** [Shridhar Kirtane](https://github.com/shridhar3902)

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How to Report Bugs](#how-to-report-bugs)
- [How to Suggest Features](#how-to-suggest-features)
- [Development Setup](#development-setup)
- [Pull Request Process](#pull-request-process)
- [Code Style](#code-style)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Be kind, constructive, and professional in all interactions.

---

## How to Report Bugs

If you find a bug, please open a [GitHub Issue](https://github.com/shridhar3902/DomaScan/issues) with the following information:

1. **Description** — A clear and concise description of the bug.
2. **Steps to Reproduce** — Detailed steps to reproduce the behavior.
3. **Expected Behavior** — What you expected to happen.
4. **Actual Behavior** — What actually happened.
5. **Screenshots / Logs** — If applicable, include terminal output or screenshots.
6. **Environment** — Your OS, Python version, and DomaScan version.

> **Tip:** Use the bug report issue template if one is available.

---

## How to Suggest Features

We welcome feature ideas! To suggest a feature:

1. Open a [GitHub Issue](https://github.com/shridhar3902/DomaScan/issues) with the **"Feature Request"** label.
2. Describe the feature and the problem it solves.
3. Provide any relevant examples, mockups, or references.
4. Explain why this feature would be valuable to DomaScan users.

---

## Development Setup

Follow these steps to set up your local development environment:

### Prerequisites

- Python 3.8 or higher
- `pip` package manager
- `git`

### Steps

```bash
# 1. Fork and clone the repository
git clone https://github.com/<your-username>/DomaScan.git
cd DomaScan

# 2. Create a virtual environment
python -m venv venv

# 3. Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Install the package in development mode
pip install -e .

# 6. Verify the installation
domascan --help
```

---

## Pull Request Process

1. **Fork** the repository and create a new branch from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** in the new branch. Keep commits focused and well-described.

3. **Test your changes** thoroughly before submitting.

4. **Update documentation** if your changes affect usage, CLI options, or module behavior.

5. **Push** your branch and open a Pull Request against the `main` branch:
   ```bash
   git push origin feature/your-feature-name
   ```

6. In the PR description:
   - Clearly describe what you changed and why.
   - Reference any related issues (e.g., `Closes #42`).
   - Include screenshots or terminal output if applicable.

7. **Wait for review** — The maintainer will review your PR and may request changes. Please respond to feedback promptly.

### PR Checklist

- [ ] Code follows PEP 8 style guidelines
- [ ] All existing tests pass
- [ ] New functionality includes appropriate documentation
- [ ] Commit messages are clear and descriptive
- [ ] No unnecessary files are included (check `.gitignore`)

---

## Code Style

This project follows **[PEP 8](https://peps.python.org/pep-0008/)** — the official Python style guide.

### Key Points

- **Indentation:** 4 spaces (no tabs).
- **Line Length:** Maximum 120 characters.
- **Imports:** Group in order — standard library, third-party, local. Separate groups with a blank line.
- **Naming Conventions:**
  - `snake_case` for functions and variables
  - `PascalCase` for classes
  - `UPPER_SNAKE_CASE` for constants
- **Docstrings:** Use triple double-quotes (`"""`) for all public modules, classes, and functions.
- **Type Hints:** Encouraged for function signatures.

### Linting

We recommend using a linter to check your code before submitting:

```bash
# Install flake8
pip install flake8

# Run linter
flake8 domascan/ --max-line-length=120
```

---

## Questions?

If you have any questions, feel free to open an issue or reach out to the project maintainer **Shridhar Kirtane**.

Thank you for contributing to DomaScan! 🚀
