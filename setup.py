from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="django-azuread-token-validator",
    version="0.1.8",
    description="Django middleware to validate Azure AD JWT tokens and enrich requests with user data",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Marlon Passos",
    author_email="marlonjbpassos@gmail.com",
    packages=find_packages(),
    install_requires=[
        "Django>=3.2",
        "PyJWT>=2.0",
        "requests>=2.25",
        "cryptography>=40.0.0",
    ],
    python_requires=">=3.7",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.1",
        "Framework :: Django :: 4.2",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Operating System :: OS Independent",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: Session",
        "Topic :: Security",
    ],
    keywords="django azure ad jwt middleware authentication sso drf",
)
