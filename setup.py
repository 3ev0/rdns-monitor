import setuptools
setuptools.setup(
    name = "rDNS-Monitor",
    version = "0.1",
    packages = ["rdnsmonitor"],
    author = "3v0o",
    description = "Reverse DNS monitor. Queries and stores PTR records of all IPv4 addresses.",
    license = "Apache",
    entry_points = {
        'console_scripts': ['rdnsmonitor = rdnsmonitor.cli:main']
    }
)
